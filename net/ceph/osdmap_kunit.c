// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for OSD map decoding and PG mapping, included from osdmap.c
 * for its static functions.
 */
#include <kunit/test.h>

#include "osdmap_kunit.h"

static void varint64_test(struct kunit *test)
{
	static const struct {
		u8 buf[10];
		int len;
		u64 val;
	} cases[] = {
		{ { 0x00 }, 1, 0 },
		{ { 0x7f }, 1, 127 },
		{ { 0x80, 0x01 }, 2, 128 },
		{ { 0xff, 0xff, 0x03 }, 3, 65535 },
		{ { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		    0x01 },
		  10, 1ULL << 63 },
		{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		    0x01 },
		  10, U64_MAX },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		void *p = (void *)cases[i].buf;
		void *end = p + cases[i].len;
		u64 v;

		KUNIT_EXPECT_EQ(test, ceph_decode_varint64(&p, end, &v), 0);
		KUNIT_EXPECT_EQ(test, v, cases[i].val);
		KUNIT_EXPECT_PTR_EQ(test, p, end);
	}
}

static void varint64_bad_test(struct kunit *test)
{
	static const u8 buf[11] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
				    0x80, 0x80, 0x80, 0x80, 0x01 };
	void *p;
	u64 v;

	/* truncated */
	p = (void *)buf;
	KUNIT_EXPECT_EQ(test, ceph_decode_varint64(&p, p + 2, &v), -EINVAL);

	/* more than 64 bits */
	p = (void *)buf;
	KUNIT_EXPECT_EQ(test, ceph_decode_varint64(&p, p + 11, &v), -EINVAL);
}

static void shard_id_set_test(struct kunit *test)
{
	/* {1, 3} in the first word, {66} in the second */
	static const u8 buf[] = { 0x0a, 0x04 };
	DECLARE_BITMAP(bits, CEPH_POOL_MAX_SHARDS);
	void *p = (void *)buf;

	KUNIT_ASSERT_EQ(test, decode_shard_id_set(&p, p + sizeof(buf), bits),
			0);
	KUNIT_EXPECT_EQ(test, bitmap_weight(bits, CEPH_POOL_MAX_SHARDS), 3);
	KUNIT_EXPECT_TRUE(test, test_bit(1, bits));
	KUNIT_EXPECT_TRUE(test, test_bit(3, bits));
	KUNIT_EXPECT_TRUE(test, test_bit(66, bits));
}

static const struct test_pool ec_pool = {
	.v = 34,
	.type = CEPH_POOL_TYPE_EC,
	.size = 3,
	.pg_num = 8,
	.flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS,
	.stripe_width = 8192,
	.ec_data_shard_count = -1,
	.migration_src = -1,
	.migration_target = -1,
	.migration_root = -1,
	.num_zones = 1,
};

static void encode_varint64(void **p, u64 v)
{
	while (v >= 0x80) {
		ceph_encode_8(p, (v & 0x7f) | 0x80);
		v >>= 7;
	}
	ceph_encode_8(p, v);
}

static void encode_optional_pool_id(void **p, s64 id)
{
	ceph_encode_8(p, id >= 0);
	if (id >= 0)
		ceph_encode_64(p, id);
}

/* pg_pool_t::encode() of version @tp->v (29 or later) */
static size_t encode_pool(void *buf, const struct test_pool *tp)
{
	void *p = buf, *len;
	int i;

	ceph_encode_8(&p, tp->v);
	ceph_encode_8(&p, 5);
	len = p;
	p += 4;
	ceph_encode_8(&p, tp->type);
	ceph_encode_8(&p, tp->size);
	ceph_encode_8(&p, tp->crush_rule);
	ceph_encode_8(&p, CEPH_STR_HASH_RJENKINS);
	ceph_encode_32(&p, tp->pg_num);
	ceph_encode_32(&p, tp->pgp_num ?: tp->pg_num);
	ceph_encode_64(&p, 0);			/* lpg_num, lpgp_num */
	ceph_encode_32(&p, 1);			/* last_change */
	ceph_encode_64(&p, 0);			/* snap_seq */
	ceph_encode_32(&p, 0);			/* snap_epoch */
	ceph_encode_32(&p, 0);			/* snaps */
	ceph_encode_32(&p, 0);			/* removed_snaps */
	ceph_encode_64(&p, 0);			/* auid */
	ceph_encode_64(&p, tp->flags);
	ceph_encode_32(&p, 0);			/* crash_replay_interval */
	ceph_encode_8(&p, tp->min_size ?: tp->size - 1);
	ceph_encode_64(&p, 0);			/* quota_max_bytes */
	ceph_encode_64(&p, 0);			/* quota_max_objects */
	if (tp->tier) {
		ceph_encode_32(&p, 1);		/* tiers */
		ceph_encode_64(&p, tp->tier);
	} else {
		ceph_encode_32(&p, 0);
	}
	ceph_encode_64(&p, tp->tier_of ?: -1);
	ceph_encode_8(&p, 0);			/* cache_mode */
	ceph_encode_64(&p, -1);			/* read_tier */
	ceph_encode_64(&p, -1);			/* write_tier */
	ceph_encode_32(&p, 0);			/* properties */
	ceph_start_encoding(&p, 1, 1, 1);	/* hit_set_params */
	ceph_encode_8(&p, 0);
	ceph_encode_64(&p, 0);			/* hit_set_period, _count */
	ceph_encode_32(&p, tp->stripe_width);
	ceph_encode_64(&p, 0);			/* target_max_bytes */
	ceph_encode_64(&p, 0);			/* target_max_objects */
	ceph_encode_64(&p, 0);			/* cache_target_*_ratio_micro */
	ceph_encode_64(&p, 0);			/* cache_min_*_age */
	ceph_encode_32(&p, 0);			/* erasure_code_profile */
	ceph_encode_32(&p, 0);			/* last_force_op_resend_pre* */
	ceph_encode_32(&p, 0);		/* min_read_recency_for_promote */
	ceph_encode_64(&p, 0);			/* expected_num_objects */
	ceph_encode_32(&p, 0);			/* v19 */
	ceph_encode_32(&p, 0);			/* v20 */
	ceph_encode_8(&p, 0);			/* v21 */
	ceph_encode_8(&p, 0);			/* v22 */
	ceph_encode_64(&p, 0);			/* v23 */
	if (tp->dedup_tier) {			/* v24 opts */
		ceph_start_encoding(&p, 2, 1, 4 + 4 + 4 + 8);
		ceph_encode_32(&p, 1);
		ceph_encode_32(&p, 20);		/* DEDUP_TIER */
		ceph_encode_32(&p, 1);		/* INT */
		ceph_encode_64(&p, tp->dedup_tier);
	} else {
		ceph_start_encoding(&p, 2, 1, 4);
		ceph_encode_32(&p, 0);
	}
	ceph_encode_32(&p, tp->last_force_resend);	/* v25 */
	ceph_encode_32(&p, 0);			/* v26 application_metadata */
	ceph_encode_64(&p, 0);			/* v27 create_time */
	for (i = 0; i < 6; i++)			/* v28 */
		ceph_encode_32(&p, i < 3 ? tp->pg_num : 0);
	ceph_encode_8(&p, 0);
	ceph_start_encoding(&p, 1, 1, 8);	/* v29 last_pg_merge_meta */
	ceph_encode_64(&p, 0);
	if (tp->v == 30) {
		for (i = 0; i < 4; i++)
			ceph_encode_32(&p, 1);
	}
	if (tp->v >= 31) {
		ceph_encode_8(&p, 1);
		for (i = 0; i < 4; i++)
			ceph_encode_32(&p, 1);
	}
	if (tp->v >= 32) {
		encode_varint64(&p, tp->nonprimary_shards[0]);
		encode_varint64(&p, tp->nonprimary_shards[1]);
	}
	if (tp->v >= 33) {
		ceph_encode_32(&p, tp->shard_mapping_len);
		for (i = 0; i < tp->shard_mapping_len; i++)
			ceph_encode_8(&p, tp->shard_mapping[i]);
		ceph_encode_8(&p, tp->ec_data_shard_count >= 0);
		if (tp->ec_data_shard_count >= 0)
			ceph_encode_8(&p, tp->ec_data_shard_count);
		ceph_encode_8(&p, 1);		/* ec_coding_shard_count */
		ceph_encode_8(&p, 1);
	}
	if (tp->v >= 34) {
		encode_optional_pool_id(&p, tp->migration_src);
		encode_optional_pool_id(&p, tp->migration_target);
		ceph_encode_32(&p, tp->num_migrating_pgs);
		for (i = 0; i < tp->num_migrating_pgs; i++) {
			ceph_encode_8(&p, 1);
			ceph_encode_64(&p, tp->id ?: 1);
			ceph_encode_32(&p, tp->migrating_pgs[i]);
			ceph_encode_32(&p, -1);
		}
		ceph_encode_32(&p, tp->lowest_migrated_pg);
		encode_optional_pool_id(&p, tp->migration_root);
	}
	if (tp->v >= 35) {
		/* replica */
		ceph_encode_8(&p, tp->num_zones ? tp->size / tp->num_zones : 0);
		ceph_encode_8(&p, tp->num_zones);
	}
	put_unaligned_le32(p - len - 4, len);
	return p - buf;
}

static int test_decode_pool(struct kunit *test, const struct test_pool *tp,
			    struct ceph_pg_pool_info *pi)
{
	void *buf = kunit_kzalloc(test, 1024, GFP_KERNEL);
	size_t len;
	void *p;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, buf);
	len = encode_pool(buf, tp);
	p = buf;
	ret = decode_pool(&p, buf + len, pi);
	if (!ret)
		KUNIT_EXPECT_PTR_EQ(test, p, buf + len);
	return ret;
}

static void pool_v29_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {};
	struct test_pool tp = ec_pool;

	tp.v = 29;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, pi.type, CEPH_POOL_TYPE_EC);
	KUNIT_EXPECT_EQ(test, pi.size, 3);
	KUNIT_EXPECT_EQ(test, pi.stripe_width, 8192);
	KUNIT_EXPECT_TRUE(test, bitmap_empty(pi.nonprimary_shards,
					     CEPH_POOL_MAX_SHARDS));
	KUNIT_EXPECT_EQ(test, pi.shard_mapping_len, 0);
	KUNIT_EXPECT_EQ(test, pi.ec_data_shard_count, 0);
	KUNIT_EXPECT_EQ(test, pi.migration_src, -1);
	KUNIT_EXPECT_EQ(test, pi.migration_target, -1);
	KUNIT_EXPECT_EQ(test, pi.migration_root, -1);
	KUNIT_EXPECT_EQ(test, pi.num_migrating_pgs, 0);
}

static void pool_v33_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {};
	struct test_pool tp = ec_pool;

	tp.v = 33;
	tp.nonprimary_shards[0] = BIT(1);
	tp.shard_mapping_len = 3;
	tp.shard_mapping[0] = 0;
	tp.shard_mapping[1] = 2;
	tp.shard_mapping[2] = 1;
	tp.ec_data_shard_count = 2;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, bitmap_weight(pi.nonprimary_shards,
					    CEPH_POOL_MAX_SHARDS), 1);
	KUNIT_EXPECT_TRUE(test, test_bit(1, pi.nonprimary_shards));
	KUNIT_EXPECT_EQ(test, pi.shard_mapping_len, 3);
	KUNIT_EXPECT_EQ(test, pi.shard_mapping[1], 2);
	KUNIT_EXPECT_EQ(test, pi.shard_mapping[2], 1);
	KUNIT_EXPECT_EQ(test, pi.ec_data_shard_count, 2);

	/* a mapping wider than any PG is kept by its length only */
	tp.shard_mapping_len = 40;
	tp.ec_data_shard_count = -1;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, pi.shard_mapping_len, 40);
	KUNIT_EXPECT_EQ(test, pi.ec_data_shard_count, 0);
}

static void pool_v34_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {};
	struct test_pool tp = ec_pool;

	/* a migration source */
	tp.migration_target = 7;
	tp.num_migrating_pgs = 3;
	tp.migrating_pgs[0] = 1;
	tp.migrating_pgs[1] = 4;
	tp.migrating_pgs[2] = 6;
	tp.lowest_migrated_pg = 5;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, pi.migration_src, -1);
	KUNIT_EXPECT_EQ(test, pi.migration_target, 7);
	KUNIT_EXPECT_EQ(test, pi.migration_root, -1);
	KUNIT_ASSERT_EQ(test, pi.num_migrating_pgs, 3);
	KUNIT_EXPECT_EQ(test, pi.migrating_pgs[0], 1);
	KUNIT_EXPECT_EQ(test, pi.migrating_pgs[1], 4);
	KUNIT_EXPECT_EQ(test, pi.migrating_pgs[2], 6);
	KUNIT_EXPECT_EQ(test, pi.lowest_migrated_pg, 5);

	/* its target: the old state goes away */
	tp = ec_pool;
	tp.migration_src = 2;
	tp.migration_root = 2;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, pi.migration_src, 2);
	KUNIT_EXPECT_EQ(test, pi.migration_target, -1);
	KUNIT_EXPECT_EQ(test, pi.migration_root, 2);
	KUNIT_EXPECT_EQ(test, pi.num_migrating_pgs, 0);
	KUNIT_EXPECT_NULL(test, pi.migrating_pgs);
}

static void pool_v35_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {};
	struct test_pool tp = ec_pool;

	tp.v = 35;
	tp.size = 6;
	tp.num_zones = 2;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, pi.num_zones, 2);
	KUNIT_EXPECT_EQ(test, ceph_pool_zone_size(&pi), 3);
	KUNIT_EXPECT_EQ(test, ceph_pool_relative_shard(&pi, 4), 1);

	/* earlier encodings are of one zone */
	tp.v = 34;
	KUNIT_ASSERT_EQ(test, test_decode_pool(test, &tp, &pi), 0);
	KUNIT_EXPECT_EQ(test, pi.num_zones, 1);

	/* zones must divide the pool */
	tp.v = 35;
	tp.num_zones = 4;
	KUNIT_EXPECT_EQ(test, test_decode_pool(test, &tp, &pi), -EINVAL);
	tp.num_zones = 0;
	KUNIT_EXPECT_EQ(test, test_decode_pool(test, &tp, &pi), -EINVAL);

	/* nor a pool of size 0: the zone helpers divide by the zone size */
	tp.num_zones = 1;
	tp.size = 0;
	tp.min_size = 1;
	KUNIT_EXPECT_EQ(test, test_decode_pool(test, &tp, &pi), -EINVAL);
	tp.v = 34;
	KUNIT_EXPECT_EQ(test, test_decode_pool(test, &tp, &pi), -EINVAL);
}

/* Every cut short encoding is refused, without reading past the end. */
static void pool_truncated_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {};
	struct test_pool tp = ec_pool;
	void *buf = kunit_kzalloc(test, 1024, GFP_KERNEL);
	size_t len, cut;

	KUNIT_ASSERT_NOT_NULL(test, buf);
	tp.nonprimary_shards[0] = BIT(1);
	tp.shard_mapping_len = 2;
	tp.ec_data_shard_count = 2;
	tp.migration_target = 7;
	tp.num_migrating_pgs = 2;
	tp.migrating_pgs[1] = 3;
	tp.migration_root = 2;
	len = encode_pool(buf, &tp);

	for (cut = 6; cut < len; cut++) {
		void *copy = kunit_kmalloc(test, cut, GFP_KERNEL);
		void *p = copy;

		KUNIT_ASSERT_NOT_NULL(test, copy);
		memcpy(copy, buf, cut);
		put_unaligned_le32(cut - 6, copy + 2);
		KUNIT_EXPECT_NE_MSG(test, decode_pool(&p, copy + cut, &pi), 0,
				    "cut at %zu of %zu", cut, len);
		kunit_kfree(test, copy);
	}
	kfree(pi.migrating_pgs);
}

/* CRUSH bucket types, as in a default map */
#define TEST_TYPE_HOST		1
#define TEST_TYPE_DATACENTER	8
#define TEST_TYPE_ROOT		11

static void encode_crush_bucket(void **p, int id, int type, const int *items,
				int n, u32 item_weight)
{
	int i;

	ceph_encode_32(p, CRUSH_BUCKET_STRAW2);
	ceph_encode_32(p, id);
	ceph_encode_16(p, type);
	ceph_encode_8(p, CRUSH_BUCKET_STRAW2);
	ceph_encode_8(p, CRUSH_HASH_RJENKINS1);
	ceph_encode_32(p, n * item_weight);
	ceph_encode_32(p, n);
	for (i = 0; i < n; i++)
		ceph_encode_32(p, items[i]);
	for (i = 0; i < n; i++)
		ceph_encode_32(p, item_weight);
}

/* min_size 1, as monitors encode rules for SERVER_QUINCY clients */
static void encode_crush_rule(void **p, int ruleset, int type, int max_size,
			      const int (*steps)[3], int n)
{
	int i;

	ceph_encode_32(p, 1);
	ceph_encode_32(p, n);
	ceph_encode_8(p, ruleset);
	ceph_encode_8(p, type);
	ceph_encode_8(p, 1);			/* min_size */
	ceph_encode_8(p, max_size);
	for (i = 0; i < n; i++) {
		ceph_encode_32(p, steps[i][0]);
		ceph_encode_32(p, steps[i][1]);
		ceph_encode_32(p, steps[i][2]);
	}
}

static void encode_crush_name(void **p, int id, const char *name)
{
	ceph_encode_32(p, id);
	ceph_encode_32(p, strlen(name));
	ceph_encode_copy(p, name, strlen(name));
}

/* CrushWrapper::encode() of the map in osdmap_kunit.h */
static void encode_crush(void **p, int max_size)
{
	static const int rep[][3] = {
		{ CRUSH_RULE_TAKE, -1, 0 },
		{ CRUSH_RULE_CHOOSELEAF_FIRSTN, 0, TEST_TYPE_HOST },
		{ CRUSH_RULE_EMIT, 0, 0 },
	};
	static const int ec[][3] = {
		{ CRUSH_RULE_SET_CHOOSELEAF_TRIES, 5, 0 },
		{ CRUSH_RULE_SET_CHOOSE_TRIES, 100, 0 },
		{ CRUSH_RULE_TAKE, -1, 0 },
		{ CRUSH_RULE_CHOOSELEAF_INDEP, 0, TEST_TYPE_HOST },
		{ CRUSH_RULE_EMIT, 0, 0 },
	};
	static const int ec_zones[][3] = {
		{ CRUSH_RULE_SET_CHOOSELEAF_TRIES, 5, 0 },
		{ CRUSH_RULE_SET_CHOOSE_TRIES, 100, 0 },
		{ CRUSH_RULE_TAKE, -1, 0 },
		{ CRUSH_RULE_CHOOSE_INDEP, 2, TEST_TYPE_DATACENTER },
		{ CRUSH_RULE_CHOOSELEAF_INDEP, 3, TEST_TYPE_HOST },
		{ CRUSH_RULE_EMIT, 0, 0 },
	};
	static const int dcs[] = { -2, -3 };
	char name[16];
	int items[3];
	int i;

	ceph_encode_32(p, CRUSH_MAGIC);
	ceph_encode_32(p, 9);			/* max_buckets */
	ceph_encode_32(p, 3);			/* max_rules */
	ceph_encode_32(p, TEST_MAX_OSD);	/* max_devices */

	/* default (-1), dc0 and dc1 (-2, -3), host0..host5 (-4..-9) */
	encode_crush_bucket(p, -1, TEST_TYPE_ROOT, dcs, 2, 6 << 16);
	for (i = 0; i < 2; i++) {
		items[0] = -4 - 3 * i;
		items[1] = -5 - 3 * i;
		items[2] = -6 - 3 * i;
		encode_crush_bucket(p, -2 - i, TEST_TYPE_DATACENTER, items, 3,
				    2 << 16);
	}
	for (i = 0; i < 6; i++) {
		items[0] = 2 * i;
		items[1] = 2 * i + 1;
		encode_crush_bucket(p, -4 - i, TEST_TYPE_HOST, items, 2,
				    1 << 16);
	}

	encode_crush_rule(p, TEST_RULE_REP, CEPH_POOL_TYPE_REP, max_size,
			  rep, ARRAY_SIZE(rep));
	encode_crush_rule(p, TEST_RULE_EC, CEPH_POOL_TYPE_EC, max_size,
			  ec, ARRAY_SIZE(ec));
	encode_crush_rule(p, TEST_RULE_EC_ZONES, CEPH_POOL_TYPE_EC, max_size,
			  ec_zones, ARRAY_SIZE(ec_zones));

	ceph_encode_32(p, 4);			/* type names */
	encode_crush_name(p, 0, "osd");
	encode_crush_name(p, TEST_TYPE_HOST, "host");
	encode_crush_name(p, TEST_TYPE_DATACENTER, "datacenter");
	encode_crush_name(p, TEST_TYPE_ROOT, "root");

	ceph_encode_32(p, 9 + TEST_MAX_OSD);	/* names */
	encode_crush_name(p, -1, "default");
	for (i = 0; i < 2; i++) {
		snprintf(name, sizeof(name), "dc%d", i);
		encode_crush_name(p, -2 - i, name);
	}
	for (i = 0; i < 6; i++) {
		snprintf(name, sizeof(name), "host%d", i);
		encode_crush_name(p, -4 - i, name);
	}
	for (i = 0; i < TEST_MAX_OSD; i++) {
		snprintf(name, sizeof(name), "osd.%d", i);
		encode_crush_name(p, i, name);
	}

	ceph_encode_32(p, 0);			/* rule names */

	/* the tunables of a current map */
	ceph_encode_32(p, 0);			/* choose_local_tries */
	ceph_encode_32(p, 0);		/* choose_local_fallback_tries */
	ceph_encode_32(p, 50);			/* choose_total_tries */
	ceph_encode_32(p, 1);			/* chooseleaf_descend_once */
	ceph_encode_8(p, 1);			/* chooseleaf_vary_r */
	ceph_encode_8(p, 1);			/* straw_calc_version */
	ceph_encode_32(p, 0x36);		/* allowed_bucket_algs */
	ceph_encode_8(p, 1);			/* chooseleaf_stable */
}

static void encode_pgid(void **p, s64 pool, u32 seed)
{
	ceph_encode_8(p, 1);
	ceph_encode_64(p, pool);
	ceph_encode_32(p, seed);
	ceph_encode_32(p, -1);			/* preferred */
}

/*
 * OSDMap::encode() of the client part, version 10, with no OSD addresses.
 * @buf must have room for TEST_OSDMAP_BUF_LEN bytes.
 */
size_t ceph_kunit_encode_osdmap(void *buf, const struct test_osdmap *tm)
{
	void *p = buf, *wrapper, *client, *crush;
	s64 pool_max = 0;
	int i, j;

	ceph_encode_8(&p, 8);
	ceph_encode_8(&p, 7);
	wrapper = p;
	p += 4;
	ceph_encode_8(&p, 10);
	ceph_encode_8(&p, 1);
	client = p;
	p += 4;

	memset(p, 0, 16);			/* fsid */
	p += 16;
	ceph_encode_32(&p, tm->epoch);
	ceph_encode_64(&p, 0);			/* created */
	ceph_encode_64(&p, 0);			/* modified */

	ceph_encode_32(&p, tm->num_pools);
	for (i = 0; i < tm->num_pools; i++) {
		const struct test_pool *tp = &tm->pools[i];

		ceph_encode_64(&p, tp->id ?: 1);
		p += encode_pool(p, tp);
		pool_max = max(pool_max, tp->id ?: 1);
	}
	ceph_encode_32(&p, 0);			/* pool names */
	ceph_encode_32(&p, pool_max);
	ceph_encode_32(&p, tm->flags);

	ceph_encode_32(&p, TEST_MAX_OSD);
	ceph_encode_32(&p, TEST_MAX_OSD);
	for (i = 0; i < TEST_MAX_OSD; i++)
		ceph_encode_32(&p, CEPH_OSD_EXISTS |
				   (tm->down & BIT(i) ? 0 : CEPH_OSD_UP));
	ceph_encode_32(&p, TEST_MAX_OSD);
	for (i = 0; i < TEST_MAX_OSD; i++)
		ceph_encode_32(&p, tm->out & BIT(i) ? CEPH_OSD_OUT :
						      CEPH_OSD_IN);
	ceph_encode_32(&p, TEST_MAX_OSD);
	for (i = 0; i < TEST_MAX_OSD; i++) {
		ceph_encode_8(&p, 2);		/* an empty entity_addrvec_t */
		ceph_encode_32(&p, 0);
	}

	ceph_encode_32(&p, tm->num_pg_temp);
	for (i = 0; i < tm->num_pg_temp; i++) {
		const struct test_pg_mapping *m = &tm->pg_temp[i];

		encode_pgid(&p, m->pool, m->seed);
		ceph_encode_32(&p, m->len);
		for (j = 0; j < m->len; j++)
			ceph_encode_32(&p, m->osds[j]);
	}
	ceph_encode_32(&p, tm->num_primary_temp);
	for (i = 0; i < tm->num_primary_temp; i++) {
		encode_pgid(&p, tm->primary_temp[i].pool,
			    tm->primary_temp[i].seed);
		ceph_encode_32(&p, tm->primary_temp[i].osds[0]);
	}
	ceph_encode_32(&p, 0);			/* primary_affinity */

	crush = p;
	p += 4;
	encode_crush(&p, tm->rule_max_size ?: 100);
	put_unaligned_le32(p - crush - 4, crush);

	ceph_encode_32(&p, 0);			/* erasure_code_profiles */
	ceph_encode_32(&p, 0);			/* pg_upmap */
	ceph_encode_32(&p, 0);			/* pg_upmap_items */
	ceph_encode_32(&p, 1);			/* crush_version */
	ceph_encode_32(&p, 0);			/* new_removed_snaps */
	ceph_encode_32(&p, 0);			/* new_purged_snaps */
	ceph_encode_64(&p, 0);			/* last_up_change */
	ceph_encode_64(&p, 0);			/* last_in_change */
	ceph_encode_32(&p, tm->num_upmap_primaries);
	for (i = 0; i < tm->num_upmap_primaries; i++) {
		encode_pgid(&p, tm->upmap_primaries[i].pool,
			    tm->upmap_primaries[i].seed);
		ceph_encode_32(&p, tm->upmap_primaries[i].osds[0]);
	}

	put_unaligned_le32(p - client - 4, client);
	put_unaligned_le32(p - wrapper - 4, wrapper);
	return p - buf;
}

/* A copy of @tm to change, too big for the stack */
struct test_osdmap *ceph_kunit_osdmap_dup(struct kunit *test,
					  const struct test_osdmap *tm)
{
	struct test_osdmap *copy = kunit_kmalloc(test, sizeof(*copy),
						 GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, copy);
	*copy = *tm;
	return copy;
}

struct ceph_osdmap *ceph_kunit_osdmap(struct kunit *test,
				      const struct test_osdmap *tm)
{
	void *buf = kunit_kzalloc(test, TEST_OSDMAP_BUF_LEN, GFP_KERNEL);
	struct ceph_osdmap *map;
	size_t len;
	void *p;

	KUNIT_ASSERT_NOT_NULL(test, buf);
	len = ceph_kunit_encode_osdmap(buf, tm);
	KUNIT_ASSERT_LE(test, len, TEST_OSDMAP_BUF_LEN);

	p = buf;
	map = ceph_osdmap_decode(&p, buf + len, false);
	KUNIT_ASSERT_FALSE(test, IS_ERR(map));
	kunit_kfree(test, buf);
	return map;
}

static struct ceph_osdmap *test_map(struct kunit *test, int max_osd)
{
	struct ceph_osdmap *map = ceph_osdmap_alloc();
	int i;

	KUNIT_ASSERT_NOT_NULL(test, map);
	KUNIT_ASSERT_EQ(test, osdmap_set_max_osd(map, max_osd), 0);
	map->max_osd = max_osd;
	for (i = 0; i < max_osd; i++) {
		map->osd_state[i] = CEPH_OSD_EXISTS | CEPH_OSD_UP;
		map->osd_weight[i] = CEPH_OSD_IN;
	}
	return map;
}

static void test_add_mapping(struct kunit *test, struct rb_root *root,
			     const struct ceph_pg *pgid, const int *osds,
			     int len)
{
	struct ceph_pg_mapping *pg = alloc_pg_mapping(len * sizeof(u32));
	int i;

	KUNIT_ASSERT_NOT_NULL(test, pg);
	pg->pgid = *pgid; /* struct */
	pg->pg_temp.len = len;
	for (i = 0; i < len; i++)
		pg->pg_temp.osds[i] = osds[i];
	insert_pg_mapping(root, pg);
}

/*
 * Every set of non-primary shards of a 6-shard pool (shard 0 never is
 * one): a pg_temp stored with the shards that can be primary first
 * (OSDMap::pgtemp_primaryfirst()) comes back in shard order.
 */
static void primaryfirst_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {
		.id = 1,
		.type = CEPH_POOL_TYPE_EC,
		.size = 6,
		.flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS,
		.num_zones = 1,
	};
	struct ceph_pg pgid = { .pool = 1, .seed = 0 };
	struct ceph_osdmap *map = test_map(test, 16);
	int set, shard;

	for (set = 2; set < 64; set += 2) {
		struct ceph_pg_mapping *pg;
		struct ceph_osds temp;
		int pg_temp[6], n = 0;

		bitmap_zero(pi.nonprimary_shards, CEPH_POOL_MAX_SHARDS);
		for (shard = 0; shard < 6; shard++) {
			if (set & BIT(shard))
				__set_bit(shard, pi.nonprimary_shards);
			else
				pg_temp[n++] = 10 + shard;
		}
		for (shard = 0; shard < 6; shard++) {
			if (set & BIT(shard))
				pg_temp[n++] = 10 + shard;
		}

		test_add_mapping(test, &map->pg_temp, &pgid, pg_temp, 6);
		get_temp_osds(map, &pi, &pgid, &temp);
		KUNIT_EXPECT_EQ(test, temp.primary, 10);
		for (shard = 0; shard < 6; shard++)
			KUNIT_EXPECT_EQ_MSG(test, temp.osds[shard], 10 + shard,
					    "set %x shard %d", set, shard);

		pg = lookup_pg_mapping(&map->pg_temp, &pgid);
		erase_pg_mapping(&map->pg_temp, pg);
		free_pg_mapping(pg);
	}
	ceph_osdmap_destroy(map);
}

/* 2+1 over two zones: shard 1 of each zone can't be primary */
static void primaryfirst_zones_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {
		.id = 1,
		.type = CEPH_POOL_TYPE_EC,
		.size = 6,
		.flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS,
		.num_zones = 2,
	};
	struct ceph_pg pgid = { .pool = 1, .seed = 0 };
	static const int pg_temp[] = { 10, 12, 13, 15, 11, 14 };
	struct ceph_osdmap *map = test_map(test, 16);
	struct ceph_osds temp;
	int shard;

	__set_bit(1, pi.nonprimary_shards);
	__set_bit(4, pi.nonprimary_shards);
	test_add_mapping(test, &map->pg_temp, &pgid, pg_temp, 6);
	get_temp_osds(map, &pi, &pgid, &temp);
	for (shard = 0; shard < 6; shard++)
		KUNIT_EXPECT_EQ(test, temp.osds[shard], 10 + shard);

	ceph_osdmap_destroy(map);
}

static void primaryfirst_pg_temp_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {
		.id = 1,
		.type = CEPH_POOL_TYPE_EC,
		.size = 4,
		.flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS,
		.num_zones = 1,
	};
	struct ceph_pg pgid = { .pool = 1, .seed = 0 };
	/* shards 0, 2, 3 can be primary; their OSDs first */
	static const int pg_temp[] = { 5, 3, 7, 6 };
	struct ceph_osdmap *map = test_map(test, 8);
	struct ceph_osds temp;

	__set_bit(1, pi.nonprimary_shards);
	test_add_mapping(test, &map->pg_temp, &pgid, pg_temp, 4);

	get_temp_osds(map, &pi, &pgid, &temp);
	KUNIT_EXPECT_EQ(test, temp.size, 4);
	KUNIT_EXPECT_EQ(test, temp.primary, 5);
	KUNIT_EXPECT_EQ(test, temp.osds[0], 5);
	KUNIT_EXPECT_EQ(test, temp.osds[1], 6);
	KUNIT_EXPECT_EQ(test, temp.osds[2], 3);
	KUNIT_EXPECT_EQ(test, temp.osds[3], 7);

	/* the next shard that can be primary takes over */
	map->osd_state[5] &= ~CEPH_OSD_UP;
	get_temp_osds(map, &pi, &pgid, &temp);
	KUNIT_EXPECT_EQ(test, temp.primary, 3);
	KUNIT_EXPECT_EQ(test, temp.osds[0], CRUSH_ITEM_NONE);
	KUNIT_EXPECT_EQ(test, temp.osds[2], 3);

	/* no reordering without EC optimizations */
	map->osd_state[5] |= CEPH_OSD_UP;
	pi.flags = 0;
	get_temp_osds(map, &pi, &pgid, &temp);
	KUNIT_EXPECT_EQ(test, temp.osds[1], 3);
	KUNIT_EXPECT_EQ(test, temp.osds[3], 6);

	ceph_osdmap_destroy(map);
}

static void pg_upmap_primary_test(struct kunit *test)
{
	static const struct {
		int osd;
		int expect[3];
	} cases[] = {
		{ 3, { 3, 2, 1 } },	/* moved to the front */
		{ 1, { 1, 2, 3 } },	/* already primary */
		{ 4, { 1, 2, 3 } },	/* marked out */
		{ 7, { 1, 2, 3 } },	/* not in the set */
		{ 100, { 1, 2, 3 } },	/* no such OSD */
	};
	struct ceph_pg pgid = { .pool = 1, .seed = 2 };
	struct ceph_osdmap *map = test_map(test, 8);
	int i, j;

	map->osd_weight[4] = CEPH_OSD_OUT;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct ceph_pg_mapping *pg = alloc_pg_mapping(0);
		struct ceph_osds raw = { .size = 3, .osds = { 1, 2, 3 } };

		KUNIT_ASSERT_NOT_NULL(test, pg);
		pg->pgid = pgid;
		pg->pg_upmap_primary.osd = cases[i].osd;
		insert_pg_mapping(&map->pg_upmap_primaries, pg);

		apply_upmap(map, &pgid, &raw);
		for (j = 0; j < 3; j++)
			KUNIT_EXPECT_EQ_MSG(test, raw.osds[j],
					    cases[i].expect[j], "osd%d",
					    cases[i].osd);

		erase_pg_mapping(&map->pg_upmap_primaries, pg);
		free_pg_mapping(pg);
	}
	ceph_osdmap_destroy(map);
}

/* 16 PGs each: replicated, EC 2+1 and EC 2+1 over the two datacenters */
static const struct test_osdmap crush_map = {
	.epoch = 1,
	.num_pools = 3,
	.pools = {
		{ .id = 1, .v = 35, .type = CEPH_POOL_TYPE_REP, .size = 3,
		  .crush_rule = TEST_RULE_REP, .pg_num = 16,
		  .ec_data_shard_count = -1, .migration_src = -1,
		  .migration_target = -1, .migration_root = -1,
		  .num_zones = 1 },
		{ .id = 2, .v = 35, .type = CEPH_POOL_TYPE_EC, .size = 3,
		  .crush_rule = TEST_RULE_EC, .pg_num = 16,
		  .flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS,
		  .stripe_width = 8192, .ec_data_shard_count = 2,
		  .migration_src = -1, .migration_target = -1,
		  .migration_root = -1, .num_zones = 1 },
		{ .id = 3, .v = 35, .type = CEPH_POOL_TYPE_EC, .size = 6,
		  .crush_rule = TEST_RULE_EC_ZONES, .pg_num = 16,
		  .flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS,
		  .stripe_width = 8192, .ec_data_shard_count = 2,
		  .migration_src = -1, .migration_target = -1,
		  .migration_root = -1, .num_zones = 2 },
	},
};

static void test_up_acting(struct ceph_osdmap *map, s64 pool, u32 seed,
			   struct ceph_osds *up, struct ceph_osds *acting)
{
	struct ceph_pg pgid = { .pool = pool, .seed = seed };
	struct ceph_pg_pool_info *pi = ceph_pg_pool_by_id(map, pool);

	ceph_pg_to_up_acting_osds(map, pi, &pgid, up, acting);
}

/* The map decodes, and CRUSH places every PG as its rule says. */
static void osdmap_crush_test(struct kunit *test)
{
	struct ceph_osdmap *map = ceph_kunit_osdmap(test, &crush_map);
	struct ceph_osds up, acting;
	u32 seed;
	int i;

	KUNIT_EXPECT_EQ(test, map->epoch, 1);
	KUNIT_EXPECT_EQ(test, map->max_osd, TEST_MAX_OSD);
	KUNIT_EXPECT_EQ(test, ceph_pg_pool_by_id(map, 3)->num_zones, 2);
	KUNIT_EXPECT_EQ(test, ceph_pg_pool_by_id(map, 3)->crush_ruleset,
			TEST_RULE_EC_ZONES);

	for (seed = 0; seed < 16; seed++) {
		unsigned long hosts = 0;

		/* replicated: three hosts, the primary first */
		test_up_acting(map, 1, seed, &up, &acting);
		KUNIT_ASSERT_EQ(test, acting.size, 3);
		KUNIT_EXPECT_EQ(test, acting.primary, acting.osds[0]);
		for (i = 0; i < 3; i++)
			hosts |= BIT(acting.osds[i] / 2);
		KUNIT_EXPECT_EQ_MSG(test, hweight_long(hosts), 3, "pg 1.%x",
				    seed);

		/* over zones: shards 0-2 in one datacenter, 3-5 in the other */
		test_up_acting(map, 3, seed, &up, &acting);
		KUNIT_ASSERT_EQ(test, acting.size, 6);
		hosts = 0;
		for (i = 0; i < 6; i++) {
			hosts |= BIT(acting.osds[i] / 2);
			KUNIT_EXPECT_EQ_MSG(test, acting.osds[i] / 6,
					    acting.osds[i < 3 ? 0 : 3] / 6,
					    "pg 3.%x shard %d", seed, i);
		}
		KUNIT_EXPECT_EQ_MSG(test, hweight_long(hosts), 6, "pg 3.%x",
				    seed);
		KUNIT_EXPECT_NE(test, acting.osds[0] / 6, acting.osds[3] / 6);
	}
	ceph_osdmap_destroy(map);
}

/*
 * CRUSH still picks a pool's rule by the pool's size.  Monitors encode
 * every rule's sizes as 1 to 100 for SERVER_QUINCY clients; with the
 * sizes a rule had before Quincy, a larger pool would get no OSDs.
 */
static void osdmap_crush_rule_size_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &crush_map);
	struct ceph_osdmap *map;
	struct ceph_osds up, acting;

	map = ceph_kunit_osdmap(test, tm);
	test_up_acting(map, 3, 0, &up, &acting);
	KUNIT_EXPECT_EQ(test, acting.size, 6);
	ceph_osdmap_destroy(map);

	tm->rule_max_size = 5;
	map = ceph_kunit_osdmap(test, tm);
	test_up_acting(map, 1, 0, &up, &acting);
	KUNIT_EXPECT_EQ(test, acting.size, 3);
	test_up_acting(map, 3, 0, &up, &acting);
	KUNIT_EXPECT_EQ(test, acting.size, 0);
	ceph_osdmap_destroy(map);
}

/* A down OSD leaves a hole in an EC set; an out one is replaced. */
static void osdmap_crush_down_out_test(struct kunit *test)
{
	struct ceph_osdmap *map = ceph_kunit_osdmap(test, &crush_map);
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &crush_map);
	struct ceph_osds before, after, up;
	int victim, i;

	test_up_acting(map, 2, 5, &up, &before);
	victim = before.osds[1];
	ceph_osdmap_destroy(map);

	tm->down = BIT(victim);
	map = ceph_kunit_osdmap(test, tm);
	test_up_acting(map, 2, 5, &up, &after);
	for (i = 0; i < 3; i++)
		KUNIT_EXPECT_EQ(test, after.osds[i],
				i == 1 ? CRUSH_ITEM_NONE : before.osds[i]);
	ceph_osdmap_destroy(map);

	tm->down = 0;
	tm->out = BIT(victim);
	map = ceph_kunit_osdmap(test, tm);
	test_up_acting(map, 2, 5, &up, &after);
	KUNIT_EXPECT_NE(test, after.osds[1], victim);
	KUNIT_EXPECT_NE(test, after.osds[1], CRUSH_ITEM_NONE);
	KUNIT_EXPECT_EQ(test, after.osds[0], before.osds[0]);
	KUNIT_EXPECT_EQ(test, after.osds[2], before.osds[2]);
	ceph_osdmap_destroy(map);
}

/* pg_temp (primary first), primary_temp and pg_upmap_primaries as decoded */
static void osdmap_temp_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &crush_map);
	struct test_pg_mapping *m;
	struct ceph_osdmap *map;
	struct ceph_osds up, acting;
	int upmapped;

	/* EC 2+1, shard 1 can't be primary: stored as { 4, 2, 9 } */
	tm->pools[1].nonprimary_shards[0] = BIT(1);
	tm->num_pg_temp = 1;
	m = &tm->pg_temp[0];
	m->pool = 2;
	m->seed = 3;
	m->len = 3;
	m->osds[0] = 4;
	m->osds[1] = 2;
	m->osds[2] = 9;
	tm->num_primary_temp = 1;
	m = &tm->primary_temp[0];
	m->pool = 1;
	m->seed = 4;
	m->osds[0] = 11;
	map = ceph_kunit_osdmap(test, tm);

	test_up_acting(map, 2, 3, &up, &acting);
	KUNIT_EXPECT_EQ(test, acting.osds[0], 4);
	KUNIT_EXPECT_EQ(test, acting.osds[1], 9);
	KUNIT_EXPECT_EQ(test, acting.osds[2], 2);
	KUNIT_EXPECT_EQ(test, acting.primary, 4);

	test_up_acting(map, 1, 4, &up, &acting);
	KUNIT_EXPECT_EQ(test, acting.primary, 11);

	/* an upmapped primary from the set */
	test_up_acting(map, 1, 6, &up, &acting);
	upmapped = acting.osds[2];
	ceph_osdmap_destroy(map);
	tm->num_upmap_primaries = 1;
	m = &tm->upmap_primaries[0];
	m->pool = 1;
	m->seed = 6;
	m->osds[0] = upmapped;
	map = ceph_kunit_osdmap(test, tm);
	test_up_acting(map, 1, 6, &up, &acting);
	KUNIT_EXPECT_EQ(test, up.primary, upmapped);
	KUNIT_EXPECT_EQ(test, acting.primary, upmapped);
	ceph_osdmap_destroy(map);
}

/*
 * ceph_is_new_interval() with condition @which changed: acting, up, size,
 * min_size, pg_num (a split), sort_bitwise, recovery_deletes,
 * ec_optimizations, pg_migrating, pool_pgs_migrating; -1 for none.
 */
static bool test_new_interval(int which)
{
	struct ceph_osds a = { .size = 3, .osds = { 1, 2, 3 }, .primary = 1 };
	struct ceph_osds b = { .size = 3, .osds = { 1, 2, 4 }, .primary = 1 };
	struct ceph_pg pgid = { .pool = 1, .seed = 3 };

	return ceph_is_new_interval(&a, which == 0 ? &b : &a,
				    &a, which == 1 ? &b : &a,
				    3, which == 2 ? 4 : 3,
				    2, which == 3 ? 1 : 2,
				    8, which == 4 ? 16 : 8,
				    true, which != 5,
				    true, which != 6,
				    false, which == 7,
				    false, which == 8,
				    false, which == 9,
				    &pgid);
}

static void new_interval_test(struct kunit *test)
{
	int which;

	KUNIT_EXPECT_FALSE(test, test_new_interval(-1));
	for (which = 0; which < 10; which++)
		KUNIT_EXPECT_TRUE_MSG(test, test_new_interval(which),
				      "condition %d", which);
}

static struct kunit_case ceph_osdmap_test_cases[] = {
	KUNIT_CASE(varint64_test),
	KUNIT_CASE(varint64_bad_test),
	KUNIT_CASE(shard_id_set_test),
	KUNIT_CASE(pool_v29_test),
	KUNIT_CASE(pool_v33_test),
	KUNIT_CASE(pool_v34_test),
	KUNIT_CASE(pool_v35_test),
	KUNIT_CASE(pool_truncated_test),
	KUNIT_CASE(primaryfirst_test),
	KUNIT_CASE(primaryfirst_zones_test),
	KUNIT_CASE(primaryfirst_pg_temp_test),
	KUNIT_CASE(pg_upmap_primary_test),
	KUNIT_CASE(osdmap_crush_test),
	KUNIT_CASE(osdmap_crush_rule_size_test),
	KUNIT_CASE(osdmap_crush_down_out_test),
	KUNIT_CASE(osdmap_temp_test),
	KUNIT_CASE(new_interval_test),
	{}
};

static struct kunit_suite ceph_osdmap_test_suite = {
	.name = "ceph_osdmap",
	.test_cases = ceph_osdmap_test_cases,
};

kunit_test_suite(ceph_osdmap_test_suite);
