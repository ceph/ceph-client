// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for request targeting (pool migrations, EC direct reads) and
 * EC split reads, included from osd_client.c for its static functions.
 */
#include <kunit/test.h>

#include "osdmap_kunit.h"

static void ec_direct_read_pool_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = {
		.type = CEPH_POOL_TYPE_EC,
		.size = 3,
		.flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS |
			 CEPH_POOL_FLAG_CLIENT_SPLIT_READS,
		.read_tier = -1,
		.write_tier = -1,
		.tier_of = -1,
		.num_zones = 1,
	};
	struct ceph_osd_request_target t = {
		.flags = CEPH_OSD_FLAG_READ | CEPH_OSD_FLAG_BALANCE_READS,
	};

	KUNIT_EXPECT_TRUE(test, ec_direct_read_pool(&t, &pi));

	t.flags = CEPH_OSD_FLAG_READ;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));

	/* localized reads only split for a pool over zones */
	t.flags = CEPH_OSD_FLAG_READ | CEPH_OSD_FLAG_LOCALIZE_READS;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.size = 6;
	pi.num_zones = 2;
	KUNIT_EXPECT_TRUE(test, ec_direct_read_pool(&t, &pi));

	t.flags = CEPH_OSD_FLAG_WRITE | CEPH_OSD_FLAG_BALANCE_READS;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));

	t.flags = CEPH_OSD_FLAG_READ | CEPH_OSD_FLAG_BALANCE_READS;
	pi.flags &= ~CEPH_POOL_FLAG_CLIENT_SPLIT_READS;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.flags |= CEPH_POOL_FLAG_CLIENT_SPLIT_READS | CEPH_POOL_FLAG_CRIMSON;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.flags &= ~CEPH_POOL_FLAG_CRIMSON;
	pi.flags |= CEPH_POOL_FLAG_EIO;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.flags &= ~CEPH_POOL_FLAG_EIO;
	pi.has_tiers = true;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.has_tiers = false;
	pi.tier_of = 3;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.tier_of = -1;
	pi.dedup_tier = 3;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
	pi.dedup_tier = 0;
	pi.type = CEPH_POOL_TYPE_REP;
	KUNIT_EXPECT_FALSE(test, ec_direct_read_pool(&t, &pi));
}

/* k = 2, 4 KiB chunks */
static const struct ceph_pg_pool_info ec21_pool = {
	.type = CEPH_POOL_TYPE_EC,
	.size = 3,
	.flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS |
		 CEPH_POOL_FLAG_CLIENT_SPLIT_READS,
	.read_tier = -1,
	.write_tier = -1,
	.tier_of = -1,
	.stripe_width = 8192,
	.ec_data_shard_count = 2,
	.num_zones = 1,
};

static int test_direct_read_shard(const struct ceph_pg_pool_info *pi,
				  const struct ceph_osds *acting, u64 off,
				  u64 len)
{
	struct ceph_osd_request_target t = {
		.flags = CEPH_OSD_FLAG_READ | CEPH_OSD_FLAG_BALANCE_READS,
		.ec_read_off = off,
		.ec_read_len = len,
	};

	return ec_direct_read_shard(NULL, &t, pi, acting);
}

static void ec_direct_read_shard_test(struct kunit *test)
{
	static const struct {
		u64 off, len;
		int shard;
	} cases[] = {
		{ 0, 4096, 0 },
		{ 4096, 4096, 1 },
		{ 8192, 100, 0 },	/* the next stripe */
		{ 12293, 10, 1 },
		{ 4000, 200, -1 },	/* two chunks */
		{ 0, 0, -1 },
	};
	struct ceph_pg_pool_info pi = ec21_pool;
	struct ceph_osds acting = { .size = 3, .osds = { 10, 11, 12 } };
	int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		KUNIT_EXPECT_EQ_MSG(test,
				    test_direct_read_shard(&pi, &acting,
							   cases[i].off,
							   cases[i].len),
				    cases[i].shard, "%llu~%llu",
				    cases[i].off, cases[i].len);

	/* k from the non-primary shards of a Tentacle pool */
	pi.ec_data_shard_count = 0;
	__set_bit(1, pi.nonprimary_shards);
	KUNIT_EXPECT_EQ(test, test_direct_read_shard(&pi, &acting, 4096, 1), 1);

	/* the shard mapping */
	pi.shard_mapping_len = 3;
	pi.shard_mapping[0] = 1;
	pi.shard_mapping[1] = 0;
	pi.shard_mapping[2] = 2;
	KUNIT_EXPECT_EQ(test, test_direct_read_shard(&pi, &acting, 0, 1), 1);
	pi.shard_mapping_len = 40;
	KUNIT_EXPECT_EQ(test, test_direct_read_shard(&pi, &acting, 0, 1), -1);
	pi.shard_mapping_len = 0;

	/* no OSD for the shard */
	acting.osds[1] = CRUSH_ITEM_NONE;
	KUNIT_EXPECT_EQ(test, test_direct_read_shard(&pi, &acting, 4096, 1),
			-1);
}

/* ec_shard_bytes() the slow way: byte by byte */
static u64 test_shard_bytes(u64 off, u64 len, u32 chunk, u32 k, u32 raw)
{
	u64 b, n = 0;

	for (b = off; b < off + len; b++) {
		u64 c = div_u64(b, chunk);

		if (do_div(c, k) == raw)
			n++;
	}
	return n;
}

/* Every range within three stripes of a layout, for data shard @raw. */
static void test_shard_bytes_layout(struct kunit *test, u32 chunk, u32 k,
				    u32 raw)
{
	u64 span = 3ULL * chunk * k, off, len, got, want;

	for (off = 0; off <= span; off++) {
		for (len = 0; off + len <= span; len++) {
			got = ec_shard_bytes(off, len, chunk, k, raw);
			want = test_shard_bytes(off, len, chunk, k, raw);
			KUNIT_EXPECT_EQ_MSG(test, got, want,
					    "chunk %u k %u raw %u %llu~%llu",
					    chunk, k, raw, off, len);
		}
	}
}

static void ec_shard_bytes_test(struct kunit *test)
{
	u32 chunk, k, raw;
	u64 off;

	KUNIT_EXPECT_EQ(test, ec_shard_bytes(0, 8192, 4096, 2, 0), 4096);
	KUNIT_EXPECT_EQ(test, ec_shard_bytes(0, 8192, 4096, 2, 1), 4096);
	/* 3096 + 2808 in chunks 0 and 2, 4096 in chunk 1 */
	KUNIT_EXPECT_EQ(test, ec_shard_bytes(1000, 10000, 4096, 2, 0), 5904);
	KUNIT_EXPECT_EQ(test, ec_shard_bytes(1000, 10000, 4096, 2, 1), 4096);
	KUNIT_EXPECT_EQ(test, ec_shard_bytes(4096, 4096, 4096, 4, 3), 0);

	for (k = 1; k <= 4; k++) {
		for (chunk = 1; chunk <= 5; chunk += 2) {
			for (raw = 0; raw < k; raw++)
				test_shard_bytes_layout(test, chunk, k, raw);
		}
	}

	/* a stripe_width near U32_MAX: 5 bytes into shard 1 of stripe 3 */
	chunk = 0x7ffff800;
	off = 3ULL * 2 * chunk + chunk + 5;
	KUNIT_EXPECT_EQ(test, ec_shard_bytes(off, chunk, chunk, 2, 1),
			chunk - 5);
	KUNIT_EXPECT_EQ(test, ec_shard_bytes(off, chunk, chunk, 2, 0), 5);
	/* a stripe far into a large object */
	KUNIT_EXPECT_EQ(test,
			ec_shard_bytes(1ULL << 40, 8 << 20, 1 << 20, 8, 7),
			1 << 20);
}

/* 2+1 over two zones */
static void ec_choose_read_shard_test(struct kunit *test)
{
	struct ceph_pg_pool_info pi = ec21_pool;
	struct ceph_osds acting = {
		.size = 6, .osds = { 10, 11, 12, 13, 14, 15 }
	};
	bool seen[6] = {};
	int i;

	pi.size = 6;
	pi.num_zones = 2;
	KUNIT_EXPECT_EQ(test, ec_choose_read_shard(&pi, &acting, 0, 1), 1);
	KUNIT_EXPECT_EQ(test, ec_choose_read_shard(&pi, &acting, 1, 1), 4);

	/* balanced: each zone */
	for (i = 0; i < 100; i++)
		seen[ec_choose_read_shard(&pi, &acting, -1, 1)] = true;
	KUNIT_EXPECT_TRUE(test, seen[1] && seen[4]);

	/* no OSD in the local zone: no other zone, the primary reads */
	acting.osds[4] = CRUSH_ITEM_NONE;
	KUNIT_EXPECT_EQ(test, ec_choose_read_shard(&pi, &acting, 1, 1), -1);
	/* balanced: the zone that has one */
	for (i = 0; i < 20; i++)
		KUNIT_EXPECT_EQ(test, ec_choose_read_shard(&pi, &acting, -1, 1),
				1);
}

struct migration_test {
	struct ceph_osd_client osdc;
	struct ceph_osd_request_target t;
	u32 seed;		/* raw seed of the object in pool 1 */
};

static struct ceph_pg_pool_info *test_add_pool(struct kunit *test,
					       struct ceph_osdmap *map, s64 id)
{
	struct ceph_pg_pool_info *pi = kzalloc_obj(*pi, GFP_KERNEL);
	struct rb_node **n = &map->pg_pools.rb_node, *parent = NULL;

	KUNIT_ASSERT_NOT_NULL(test, pi);
	pi->id = id;
	pi->type = CEPH_POOL_TYPE_REP;
	pi->size = 3;
	pi->object_hash = CEPH_STR_HASH_RJENKINS;
	pi->pg_num = 1;
	pi->pgp_num = 1;
	pi->read_tier = -1;
	pi->write_tier = -1;
	pi->migration_src = -1;
	pi->migration_target = -1;
	pi->migration_root = -1;
	pi->num_zones = 1;

	while (*n) {
		parent = *n;
		if (id < rb_entry(parent, struct ceph_pg_pool_info, node)->id)
			n = &parent->rb_left;
		else
			n = &parent->rb_right;
	}
	rb_link_node(&pi->node, parent, n);
	rb_insert_color(&pi->node, &map->pg_pools);
	return pi;
}

static void test_set_migrating(struct kunit *test,
			       struct ceph_pg_pool_info *pi, bool migrating)
{
	kfree(pi->migrating_pgs);
	pi->migrating_pgs = NULL;
	pi->num_migrating_pgs = 0;
	if (migrating) {
		pi->migrating_pgs = kzalloc_obj(u32, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, pi->migrating_pgs);
		pi->num_migrating_pgs = 1;	/* PG 0, the only one */
	}
}

/* Set PG 0 of pool 1's watermark, in the objects' order, past "obj"? */
static void test_set_wm(struct kunit *test, struct migration_test *mt,
			const char *name)
{
	struct ceph_pg pgid = { .pool = 1, .seed = 0 };
	struct migration_wm *mw;

	mw = lookup_migration_wm(&mt->osdc.migration_wms, &pgid);
	if (mw) {
		erase_migration_wm(&mt->osdc.migration_wms, mw);
		free_migration_wm(mw);
	}
	if (!name)
		return;

	mw = alloc_migration_wm();
	KUNIT_ASSERT_NOT_NULL(test, mw);
	mw->pgid = pgid;
	mw->wm = kzalloc_obj(*mw->wm, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, mw->wm);
	mw->wm->oid = kstrdup(name, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, mw->wm->oid);
	mw->wm->oid_len = strlen(name);
	mw->wm->snapid = CEPH_NOSNAP;
	mw->wm->hash = mt->seed;
	mw->wm->pool = 1;
	ceph_hoid_build_hash_cache(mw->wm);
	insert_migration_wm(&mt->osdc.migration_wms, mw);
}

/* The pool that calc_migration_target() sends "obj" in @pool to. */
static s64 test_route(struct kunit *test, struct migration_test *mt,
		      s64 pool)
{
	struct ceph_pg_pool_info *pi;

	pi = ceph_pg_pool_by_id(mt->osdc.osdmap, pool);
	KUNIT_ASSERT_NOT_NULL(test, pi);
	mt->t.target_oloc.pool = pool;
	if (calc_migration_target(&mt->osdc, &mt->t, &pi))
		return -ENOENT;

	KUNIT_EXPECT_EQ(test, mt->t.target_oloc.pool, pi->id);
	return pi->id;
}

static void calc_migration_target_test(struct kunit *test)
{
	struct migration_test *mt = kunit_kzalloc(test, sizeof(*mt),
						  GFP_KERNEL);
	struct ceph_pg_pool_info *src, *dst, *dst2;
	struct ceph_pg raw_pgid;

	KUNIT_ASSERT_NOT_NULL(test, mt);
	mt->osdc.osdmap = ceph_osdmap_alloc();
	KUNIT_ASSERT_NOT_NULL(test, mt->osdc.osdmap);
	mt->osdc.migration_wms = RB_ROOT;
	ceph_oid_init(&mt->t.target_oid);
	ceph_oid_printf(&mt->t.target_oid, "obj");
	ceph_oloc_init(&mt->t.target_oloc);

	src = test_add_pool(test, mt->osdc.osdmap, 1);
	dst = test_add_pool(test, mt->osdc.osdmap, 2);
	mt->t.target_oloc.pool = 1;
	__ceph_object_locator_to_pg(src, &mt->t.target_oid,
				    &mt->t.target_oloc, &raw_pgid);
	mt->seed = raw_pgid.seed;

	/* no migration */
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), 1);

	/* 1 migrates to 2, which has the name */
	src->migration_target = 2;
	dst->migration_src = 1;
	dst->migration_root = 1;
	src->lowest_migrated_pg = 1;	/* PG 0 not started */
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), 1);
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 2), 1);

	/* PG 0 migrating, below or above its watermark */
	test_set_migrating(test, src, true);
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 2), 1);
	test_set_wm(test, mt, "zzz");
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 2), 2);
	test_set_wm(test, mt, "aaa");
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 2), 1);
	test_set_wm(test, mt, NULL);

	/* PG 0 migrated */
	test_set_migrating(test, src, false);
	src->lowest_migrated_pg = 0;
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), 2);
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 2), 2);

	/* an EIO target fails the ops */
	src->lowest_migrated_pg = 1;
	dst->flags |= CEPH_POOL_FLAG_EIO;
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), 2);
	dst->flags &= ~CEPH_POOL_FLAG_EIO;

	/* finished */
	dst->migration_src = -1;
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), 2);
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 2), 2);

	/* then 2 migrates to 3: from the root, on to the latest source */
	dst2 = test_add_pool(test, mt->osdc.osdmap, 3);
	src->migration_target = 3;
	dst->migration_target = 3;
	dst->migration_root = -1;
	dst2->migration_src = 2;
	dst2->migration_root = 1;
	dst->lowest_migrated_pg = 1;
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 3), 2);
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), 2);
	dst->lowest_migrated_pg = 0;
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 3), 3);

	/* a pool that is gone */
	src->migration_target = 9;
	KUNIT_EXPECT_EQ(test, test_route(test, mt, 1), -ENOENT);

	ceph_oid_destroy(&mt->t.target_oid);
	ceph_osdmap_destroy(mt->osdc.osdmap);
}

static struct ceph_osd_request *test_alloc_req(struct kunit *test,
					       int num_ops)
{
	struct ceph_osd_request *req;

	req = kunit_kzalloc(test, struct_size(req, r_ops, num_ops),
			    GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);
	req->r_num_ops = num_ops;
	return req;
}

static struct page **test_alloc_pages(struct kunit *test, int n)
{
	struct page **pages = ceph_alloc_page_vector(n, GFP_KERNEL);

	KUNIT_ASSERT_FALSE(test, IS_ERR(pages));
	return pages;
}

/*
 * A sub-read of @shard whose versions reply has @n entries: a
 * GET_INTERNAL_VERSIONS reply if @v1.
 */
static void test_set_versions(struct kunit *test, struct ec_split_sub *sub,
			      int shard, const int (*vers)[3], int n, bool v1)
{
	struct ceph_osd_req_op *op;
	void *base, *p;
	int i;

	sub->shard = shard;
	if (!sub->req)
		sub->req = test_alloc_req(test, 2);
	op = &sub->req->r_ops[sub->req->r_num_ops - 1];
	if (!op->raw_data_in.pages) {
		op->raw_data_in.type = CEPH_OSD_DATA_TYPE_PAGES;
		op->raw_data_in.pages = test_alloc_pages(test, 1);
	}

	base = kmap_local_page(op->raw_data_in.pages[0]);
	p = base;
	if (!v1)
		ceph_start_encoding(&p, 1, 1, 4 + n * (1 + 8 + 4));
	ceph_encode_32(&p, n);
	for (i = 0; i < n; i++) {
		ceph_encode_8(&p, vers[i][0]);		/* shard */
		ceph_encode_64(&p, vers[i][1]);		/* version */
		ceph_encode_32(&p, vers[i][2]);		/* epoch */
	}
	op->outdata_len = p - base;
	kunmap_local(base);
}

static void test_free_versions(struct ceph_ec_split *sp)
{
	int i;

	for (i = 0; i < sp->num_subs; i++) {
		struct ceph_osd_request *req = sp->subs[i].req;
		struct ceph_osd_req_op *op = &req->r_ops[req->r_num_ops - 1];

		ceph_release_page_vector(op->raw_data_in.pages, 1);
	}
	kfree(sp);
}

/* A request that is never sent, to own a split read in pure tests */
static struct ceph_osd_request *test_unsent_req(struct kunit *test)
{
	struct ceph_osd_request *req = kunit_kzalloc(test, sizeof(*req),
						     GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, req);
	return req;
}

static void ec_split_versions_test(struct kunit *test)
{
	static const int same[][3] = { { 0, 5, 1 }, { 1, 5, 1 }, { 2, 5, 1 } };
	static const int newer[][3] = { { 0, 6, 1 }, { 1, 6, 1 }, { 2, 6, 1 } };
	static const int newer_epoch[][3] = {
		{ 0, 2, 2 }, { 1, 5, 1 }, { 2, 5, 1 }
	};
	static const int partial[][3] = { { 0, 6, 1 }, { 2, 6, 1 } };
	struct ceph_ec_split *sp;
	int i;

	sp = alloc_ec_split(test_unsent_req(test), 4096, 3, 3);
	KUNIT_ASSERT_NOT_NULL(test, sp);
	KUNIT_EXPECT_EQ(test, sp->num_subs, 3);

	for (i = 0; i < 3; i++)
		test_set_versions(test, &sp->subs[i], i, same, 3, false);
	KUNIT_EXPECT_TRUE(test, ec_split_versions_match(sp));

	/* shard 1 read before a write that the others saw */
	test_set_versions(test, &sp->subs[0], 0, newer, 3, false);
	test_set_versions(test, &sp->subs[2], 2, newer, 3, false);
	KUNIT_EXPECT_FALSE(test, ec_split_versions_match(sp));

	/*
	 * The newest shard, by epoch whatever the version, agrees on the
	 * others: a write of shard 0 alone.  Taking the highest version for
	 * the newest would fail it.
	 */
	test_set_versions(test, &sp->subs[0], 0, newer_epoch, 3, false);
	test_set_versions(test, &sp->subs[1], 1, same, 3, false);
	test_set_versions(test, &sp->subs[2], 2, same, 3, false);
	KUNIT_EXPECT_TRUE(test, ec_split_versions_match(sp));

	/* the newest shard doesn't know shard 1's version */
	test_set_versions(test, &sp->subs[0], 0, partial, 2, false);
	test_set_versions(test, &sp->subs[2], 2, newer, 3, false);
	KUNIT_EXPECT_FALSE(test, ec_split_versions_match(sp));

	/* shard 1 doesn't know its own */
	test_set_versions(test, &sp->subs[0], 0, newer, 3, false);
	test_set_versions(test, &sp->subs[1], 1, partial, 2, false);
	KUNIT_EXPECT_FALSE(test, ec_split_versions_match(sp));

	test_free_versions(sp);
}

static void ec_split_versions_v1_test(struct kunit *test)
{
	static const int same[][3] = { { 0, 5, 1 }, { 1, 5, 1 }, { 2, 5, 1 } };
	static const int newer[][3] = { { 0, 6, 1 }, { 1, 6, 1 }, { 2, 6, 1 } };
	static const int newer_epoch[][3] = {
		{ 0, 2, 2 }, { 1, 5, 1 }, { 2, 5, 1 }
	};
	static const int no_self[][3] = { { 0, 5, 1 }, { 1, 5, 1 } };
	static const int partial[][3] = { { 0, 5, 1 }, { 2, 5, 1 } };
	struct ceph_ec_split *sp;
	int i;

	/* data from shards 0 and 1, only versions from the primary, shard 2 */
	sp = alloc_ec_split(test_unsent_req(test), 4096, 2, 3);
	KUNIT_ASSERT_NOT_NULL(test, sp);
	sp->v1 = true;
	sp->ref = 2;
	sp->subs[2].req = test_alloc_req(test, 1);

	for (i = 0; i < 3; i++)
		test_set_versions(test, &sp->subs[i], i, same, 3, true);
	KUNIT_EXPECT_TRUE(test, ec_split_versions_match(sp));

	/* the primary needn't report its own version */
	test_set_versions(test, &sp->subs[2], 2, no_self, 2, true);
	KUNIT_EXPECT_TRUE(test, ec_split_versions_match(sp));

	/* shards 0 and 1 read before a write that the primary knows */
	test_set_versions(test, &sp->subs[2], 2, newer, 3, true);
	KUNIT_EXPECT_FALSE(test, ec_split_versions_match(sp));

	test_set_versions(test, &sp->subs[0], 0, newer, 3, true);
	test_set_versions(test, &sp->subs[1], 1, newer, 3, true);
	KUNIT_EXPECT_TRUE(test, ec_split_versions_match(sp));

	/*
	 * A write of shard 0 that the primary doesn't know yet: the primary
	 * stays the reference, where GET_INTERNAL_VERSIONS_V2 would take
	 * shard 0's.
	 */
	test_set_versions(test, &sp->subs[0], 0, newer_epoch, 3, true);
	test_set_versions(test, &sp->subs[1], 1, same, 3, true);
	test_set_versions(test, &sp->subs[2], 2, same, 3, true);
	KUNIT_EXPECT_FALSE(test, ec_split_versions_match(sp));

	/* the primary doesn't know shard 1's version */
	test_set_versions(test, &sp->subs[0], 0, same, 3, true);
	test_set_versions(test, &sp->subs[2], 2, partial, 2, true);
	KUNIT_EXPECT_FALSE(test, ec_split_versions_match(sp));

	test_free_versions(sp);
}

/* Shard @raw's chunks of [0, 3 * 4096 + 100), each filled with 'A' + c. */
static void test_set_chunks(struct kunit *test, struct ec_split_sub *sub,
			    int raw, u32 len)
{
	struct ceph_osd_req_op *op;
	u32 c, off = 0;

	sub->req = test_alloc_req(test, 2);
	sub->used = 0;
	op = &sub->req->r_ops[0];
	op->extent.osd_data.type = CEPH_OSD_DATA_TYPE_PAGES;
	op->extent.osd_data.pages = test_alloc_pages(test, 3);
	op->outdata_len = len;
	for (c = raw; off < len; c += 2) {
		u32 n = min_t(u32, 4096, len - off);
		struct page **pages = op->extent.osd_data.pages;
		char *p = kmap_local_page(pages[off >> PAGE_SHIFT]);

		memset(p + offset_in_page(off), 'A' + c, n);
		kunmap_local(p);
		off += n;
	}
}

static void ec_split_assemble_test(struct kunit *test)
{
	static const u32 lens[][2] = {
		{ 4096 + 4096, 4096 + 100 },	/* all of it */
		{ 4096 + 4096, 2000 },		/* the object ends in chunk 1 */
	};
	struct ceph_osd_request *req = test_alloc_req(test, 1);
	struct ceph_osd_req_op *op = &req->r_ops[0];
	struct ceph_ec_split *sp;
	int i, j;

	sp = alloc_ec_split(req, 4096, 2, 2);
	KUNIT_ASSERT_NOT_NULL(test, sp);
	sp->raw_sub[0] = 0;
	sp->raw_sub[1] = 1;
	op->op = CEPH_OSD_OP_READ;
	op->extent.offset = 0;
	op->extent.length = 3 * 4096 + 100;
	op->extent.osd_data.type = CEPH_OSD_DATA_TYPE_PAGES;
	op->extent.osd_data.pages = test_alloc_pages(test, 5);

	for (i = 0; i < ARRAY_SIZE(lens); i++) {
		u64 expect = lens[i][1] < 4096 ? 4096 + lens[i][1] :
						 3 * 4096 + 100;
		u64 len, off;

		test_set_chunks(test, &sp->subs[0], 0, lens[i][0]);
		test_set_chunks(test, &sp->subs[1], 1, lens[i][1]);
		len = ec_split_assemble(sp);
		KUNIT_EXPECT_EQ(test, len, expect);

		for (off = 0; off < len; off += 512) {
			struct page **pages = op->extent.osd_data.pages;
			char *p = kmap_local_page(pages[off >> PAGE_SHIFT]);
			char got = p[offset_in_page(off)];

			kunmap_local(p);
			KUNIT_EXPECT_EQ_MSG(test, got, 'A' + (int)(off / 4096),
					    "off %llu", off);
		}
		for (j = 0; j < 2; j++) {
			struct ceph_osd_req_op *sop;

			sop = &sp->subs[j].req->r_ops[0];
			ceph_release_page_vector(sop->extent.osd_data.pages, 3);
		}
	}
	ceph_release_page_vector(op->extent.osd_data.pages, 5);
	kfree(sp);
}

#define TEST_POOL_REP		1
#define TEST_POOL_EC		2	/* 2+1, 4 KiB chunks */
#define TEST_POOL_EC_ZONES	3	/* 2+1 in each of the datacenters */
#define TEST_POOL_DST		4	/* a migration target */

#define TEST_CHUNK		4096
#define TEST_USER_VERSION	1234

static struct kunit_case ceph_osd_client_test_cases[] = {
	KUNIT_CASE(ec_direct_read_pool_test),
	KUNIT_CASE(ec_direct_read_shard_test),
	KUNIT_CASE(ec_shard_bytes_test),
	KUNIT_CASE(ec_choose_read_shard_test),
	KUNIT_CASE(calc_migration_target_test),
	KUNIT_CASE(ec_split_versions_test),
	KUNIT_CASE(ec_split_versions_v1_test),
	KUNIT_CASE(ec_split_assemble_test),
	{}
};

static struct kunit_suite ceph_osd_client_test_suite = {
	.name = "ceph_osd_client",
	.test_cases = ceph_osd_client_test_cases,
};

kunit_test_suites(&ceph_osd_client_test_suite);
