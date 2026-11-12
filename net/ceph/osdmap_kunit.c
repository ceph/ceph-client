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
	ceph_encode_32(&p, tp->pg_num);		/* pgp_num */
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
	ceph_encode_32(&p, 0);			/* v25 */
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

static struct kunit_case ceph_osdmap_test_cases[] = {
	KUNIT_CASE(varint64_test),
	KUNIT_CASE(varint64_bad_test),
	KUNIT_CASE(shard_id_set_test),
	KUNIT_CASE(pool_v29_test),
	KUNIT_CASE(pool_v33_test),
	KUNIT_CASE(pool_v34_test),
	KUNIT_CASE(pool_v35_test),
	KUNIT_CASE(pool_truncated_test),
	{}
};

static struct kunit_suite ceph_osdmap_test_suite = {
	.name = "ceph_osdmap",
	.test_cases = ceph_osdmap_test_cases,
};

kunit_test_suite(ceph_osdmap_test_suite);
