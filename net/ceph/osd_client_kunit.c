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

/*
 * A client of the maps of osdmap_kunit.h with a session to every up OSD
 * that never connects: what is sent to it is dropped.  The tests play the
 * OSDs' replies through handle_reply() and new maps through
 * handle_one_map(), as the messenger would.
 */
struct test_client {
	struct ceph_client client;
	struct ceph_options opt;
};

#define TEST_POOL_REP		1
#define TEST_POOL_EC		2	/* 2+1, 4 KiB chunks */
#define TEST_POOL_EC_ZONES	3	/* 2+1 in each of the datacenters */
#define TEST_POOL_DST		4	/* a migration target */

#define TEST_CHUNK		4096
#define TEST_USER_VERSION	1234

static const struct test_osdmap client_map = {
	.epoch = 1,
	.num_pools = 4,
	.pools = {
		{ .id = TEST_POOL_REP, .v = 35, .type = CEPH_POOL_TYPE_REP,
		  .size = 3, .crush_rule = TEST_RULE_REP, .pg_num = 8,
		  .ec_data_shard_count = -1, .migration_src = -1,
		  .migration_target = -1, .migration_root = -1,
		  .lowest_migrated_pg = 8, .num_zones = 1 },
		{ .id = TEST_POOL_EC, .v = 35, .type = CEPH_POOL_TYPE_EC,
		  .size = 3, .crush_rule = TEST_RULE_EC, .pg_num = 8,
		  .flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS |
			   CEPH_POOL_FLAG_CLIENT_SPLIT_READS,
		  .stripe_width = 2 * TEST_CHUNK,
		  .nonprimary_shards = { BIT(1) },
		  .ec_data_shard_count = 2, .migration_src = -1,
		  .migration_target = -1, .migration_root = -1,
		  .lowest_migrated_pg = 8, .num_zones = 1 },
		{ .id = TEST_POOL_EC_ZONES, .v = 35, .type = CEPH_POOL_TYPE_EC,
		  .size = 6, .crush_rule = TEST_RULE_EC_ZONES, .pg_num = 8,
		  .flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS |
			   CEPH_POOL_FLAG_CLIENT_SPLIT_READS,
		  .stripe_width = 2 * TEST_CHUNK,
		  .nonprimary_shards = { BIT(1) | BIT(4) },
		  .ec_data_shard_count = 2, .migration_src = -1,
		  .migration_target = -1, .migration_root = -1,
		  .lowest_migrated_pg = 8, .num_zones = 2 },
		{ .id = TEST_POOL_DST, .v = 35, .type = CEPH_POOL_TYPE_REP,
		  .size = 3, .crush_rule = TEST_RULE_REP, .pg_num = 8,
		  .ec_data_shard_count = -1, .migration_src = -1,
		  .migration_target = -1, .migration_root = -1,
		  .lowest_migrated_pg = 8, .num_zones = 1 },
	},
};

static void test_osdc_stop(void *arg)
{
	struct ceph_osd_client *osdc = arg;

	ceph_clear_crush_locs(&osdc->client->options->crush_locs);
	ceph_osdc_stop(osdc);
}

static void test_add_sessions(struct ceph_osd_client *osdc)
{
	int o;

	verify_osdc_wrlocked(osdc);
	for (o = 0; o < osdc->osdmap->max_osd; o++) {
		if (ceph_osd_is_up(osdc->osdmap, o) &&
		    !lookup_osd(&osdc->osds, o))
			insert_osd(&osdc->osds, create_osd(osdc, o));
	}
}

/* The next map, @tm with the epoch after the client's. */
static void test_apply_map(struct kunit *test, struct ceph_osd_client *osdc,
			   const struct test_osdmap *tm)
{
	struct test_osdmap *next = ceph_kunit_osdmap_dup(test, tm);
	void *buf = kunit_kzalloc(test, TEST_OSDMAP_BUF_LEN, GFP_KERNEL);
	struct ceph_mon_client *monc = &osdc->client->monc;
	struct rb_root need_resend = RB_ROOT;
	LIST_HEAD(need_resend_linger);
	size_t len;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, buf);
	next->epoch = osdc->osdmap->epoch + 1;
	len = ceph_kunit_encode_osdmap(buf, next);

	down_write(&osdc->lock);
	ret = handle_one_map(osdc, buf, buf + len, false, &need_resend,
			     &need_resend_linger);
	test_add_sessions(osdc);
	/* the next map is wanted already: nothing to ask the monitors */
	monc->subs[CEPH_SUB_OSDMAP].want = true;
	monc->subs[CEPH_SUB_OSDMAP].item.start =
	    cpu_to_le64(osdc->osdmap->epoch + 1);
	monc->subs[CEPH_SUB_OSDMAP].item.flags = CEPH_SUBSCRIBE_ONETIME;
	kick_requests(osdc, &need_resend, &need_resend_linger);
	up_write(&osdc->lock);

	KUNIT_ASSERT_EQ(test, ret, 0);
	kunit_kfree(test, buf);
	kunit_kfree(test, next);
}

static struct ceph_osd_client *test_osdc(struct kunit *test,
					 const struct test_osdmap *tm)
{
	struct test_client *tc = kunit_kzalloc(test, sizeof(*tc), GFP_KERNEL);
	struct ceph_osd_client *osdc;

	KUNIT_ASSERT_NOT_NULL(test, tc);
	tc->opt.osd_keepalive_timeout = 3600 * HZ;
	tc->opt.osd_idle_ttl = 3600 * HZ;
	tc->opt.crush_locs = RB_ROOT;
	tc->client.options = &tc->opt;
	mutex_init(&tc->client.monc.mutex);

	osdc = &tc->client.osdc;
	KUNIT_ASSERT_EQ(test, ceph_osdc_init(osdc, &tc->client), 0);
	/* no keepalives or idle session checks: nobody to talk to */
	cancel_delayed_work_sync(&osdc->timeout_work);
	cancel_delayed_work_sync(&osdc->osds_timeout_work);
	KUNIT_ASSERT_EQ(test,
			kunit_add_action_or_reset(test, test_osdc_stop, osdc),
			0);

	test_apply_map(test, osdc, tm);
	return osdc;
}

/* The acting set of object @oid in @pool, and its PG. */
static void test_acting(struct ceph_osd_client *osdc, s64 pool,
			const char *oid, struct ceph_pg *pgid,
			struct ceph_osds *acting)
{
	struct ceph_pg_pool_info *pi = ceph_pg_pool_by_id(osdc->osdmap, pool);
	struct ceph_object_id id;
	struct ceph_object_locator oloc = { .pool = pool };
	struct ceph_osds up;
	struct ceph_pg raw;

	ceph_oid_init(&id);
	ceph_oid_printf(&id, "%s", oid);
	__ceph_object_locator_to_pg(pi, &id, &oloc, &raw);
	pgid->pool = pool;
	pgid->seed = ceph_stable_mod(raw.seed, pi->pg_num, pi->pg_num_mask);
	ceph_pg_to_up_acting_osds(osdc->osdmap, pi, &raw, &up, acting);
	ceph_oid_destroy(&id);
}

/* The byte at @off of every object in these tests */
static u8 test_byte(u64 off)
{
	return off * 7 + (off >> 12) * 31 + 1;
}

/* A read of @len bytes at @off of @oid, with its own buffer. */
static struct ceph_osd_request *test_read(struct kunit *test,
					  struct ceph_osd_client *osdc,
					  s64 pool, const char *oid,
					  int opcode, u64 off, u64 len,
					  unsigned int flags)
{
	struct ceph_osd_request *req;
	struct page **pages;

	req = ceph_osdc_alloc_request(osdc, NULL, 1, false, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);
	ceph_oid_printf(&req->r_base_oid, "%s", oid);
	req->r_base_oloc.pool = pool;
	req->r_flags = CEPH_OSD_FLAG_READ | flags;

	osd_req_op_extent_init(req, 0, opcode, off, len, 0, 0);
	pages = ceph_alloc_page_vector(calc_pages_for(0, len), GFP_KERNEL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(pages));
	osd_req_op_extent_osd_data_pages(req, 0, pages, len, 0, false, true);
	KUNIT_ASSERT_EQ(test, ceph_osdc_alloc_messages(req, GFP_KERNEL), 0);
	return req;
}

static struct page **test_pages(struct ceph_osd_request *req, int which)
{
	struct ceph_osd_req_op *op = &req->r_ops[which];

	if (op->op == CEPH_OSD_OP_READ || op->op == CEPH_OSD_OP_SPARSE_READ)
		return op->extent.osd_data.pages;
	return op->raw_data_in.pages;
}

/* The OSD @req is linked to, -1 if homeless or done. */
static int test_osd(struct ceph_osd_request *req)
{
	return req->r_osd ? req->r_osd->o_osd : -1;
}

/* @len bytes at @off of the objects are in @pages. */
static void test_check_data(struct kunit *test, struct page **pages, u64 off,
			    u64 len)
{
	u8 *buf = kunit_kmalloc(test, len, GFP_KERNEL);
	u64 i;

	KUNIT_ASSERT_NOT_NULL(test, buf);
	ceph_copy_from_page_vector(pages, buf, 0, len);
	for (i = 0; i < len; i++) {
		if (buf[i] != test_byte(off + i)) {
			KUNIT_FAIL(test, "byte %llu is %02x, not %02x",
				   off + i, buf[i], test_byte(off + i));
			break;
		}
	}
	kunit_kfree(test, buf);
}

/* @len bytes at @off of the objects into @pages, at @at. */
static void test_fill(struct kunit *test, struct page **pages, u64 at, u64 off,
		      u64 len)
{
	while (len) {
		u32 poff = offset_in_page(at);
		u32 n = min_t(u64, len, PAGE_SIZE - poff);
		u8 *p = kmap_local_page(pages[at >> PAGE_SHIFT]);
		u32 i;

		for (i = 0; i < n; i++)
			p[poff + i] = test_byte(off + i);
		kunmap_local(p);
		at += n;
		off += n;
		len -= n;
	}
}

/*
 * MOSDOpReply v8 for @req into @msg's front: @result, the ops' results
 * @rvals and data lengths @lens (NULL for 0s), and a pool migration
 * redirect to watermark @wm if not NULL.  Returns the data length.
 */
static u32 test_encode_reply(struct kunit *test, struct ceph_osd_request *req,
			     struct ceph_msg *msg, int result,
			     const int *rvals, const u32 *lens,
			     const struct ceph_hobject_id *wm)
{
	void *p = msg->front.iov_base;
	void *end = p + msg->front_alloc_len;
	u32 data_len = 0;
	int i;

	ceph_encode_string(&p, end, req->r_t.target_oid.name,
			   req->r_t.target_oid.name_len);
	ceph_encode_8(&p, 1);
	ceph_encode_64(&p, req->r_t.spgid.pgid.pool);
	ceph_encode_32(&p, req->r_t.spgid.pgid.seed);
	ceph_encode_32(&p, -1);
	ceph_encode_64(&p, CEPH_OSD_FLAG_ONDISK);
	ceph_encode_32(&p, result);
	memset(p, 0, sizeof(struct ceph_eversion));	/* bad_replay_version */
	p += sizeof(struct ceph_eversion);
	ceph_encode_32(&p, req->r_osdc->osdmap->epoch);

	ceph_encode_32(&p, req->r_num_ops);
	for (i = 0; i < req->r_num_ops; i++) {
		struct ceph_osd_op *op = p;

		memset(op, 0, sizeof(*op));
		op->op = cpu_to_le16(req->r_ops[i].op);
		op->payload_len = cpu_to_le32(lens ? lens[i] : 0);
		data_len += lens ? lens[i] : 0;
		p += sizeof(*op);
	}
	ceph_encode_32(&p, req->r_attempts - 1);	/* retry_attempt */
	for (i = 0; i < req->r_num_ops; i++)
		ceph_encode_32(&p, rvals ? rvals[i] : 0);
	memset(p, 0, sizeof(struct ceph_eversion));	/* replay_version */
	p += sizeof(struct ceph_eversion);
	ceph_encode_64(&p, TEST_USER_VERSION);

	ceph_encode_8(&p, !!wm);
	if (wm) {
		void *redir, *oloc;

		ceph_encode_8(&p, 2);
		ceph_encode_8(&p, 1);
		redir = p;
		p += 4;
		ceph_encode_8(&p, 6);
		ceph_encode_8(&p, 3);
		oloc = p;
		p += 4;
		ceph_encode_64(&p, wm->pool);
		ceph_encode_32(&p, -1);			/* preferred */
		ceph_encode_32(&p, 0);			/* key */
		ceph_encode_32(&p, 0);			/* nspace */
		ceph_encode_64(&p, -1);			/* hash */
		put_unaligned_le32(p - oloc - 4, oloc);
		ceph_encode_32(&p, 0);			/* object_name */
		ceph_encode_32(&p, 0);			/* osd_instructions */
		ceph_encode_8(&p, 1);
		encode_hoid(&p, end, wm);
		put_unaligned_le32(p - redir - 4, redir);
	}
	KUNIT_ASSERT_TRUE(test, p <= end);

	msg->front.iov_len = p - msg->front.iov_base;
	msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);
	msg->hdr.data_len = cpu_to_le32(data_len);
	msg->hdr.tid = cpu_to_le64(req->r_tid);
	msg->hdr.version = cpu_to_le16(8);
	msg->hdr.src.num = cpu_to_le64(req->r_osd->o_osd);
	return data_len;
}

/*
 * The reply of @req's OSD, its data in the request's buffers already as
 * the messenger leaves it.  @req may be gone when this returns, unless the
 * caller holds a reference.
 */
static void test_reply(struct kunit *test, struct ceph_osd_request *req,
		       int result, const int *rvals, const u32 *lens,
		       const struct ceph_hobject_id *wm)
{
	struct ceph_osd *osd = req->r_osd;
	struct ceph_msg *msg;

	KUNIT_ASSERT_NOT_NULL(test, osd);
	KUNIT_ASSERT_FALSE(test, osd_homeless(osd));
	msg = ceph_msg_get(req->r_reply);
	test_encode_reply(test, req, msg, result, rvals, lens, wm);
	handle_reply(osd, msg);
	ceph_msg_put(msg);
}

/* A whole read's reply with the objects' bytes. */
static void test_read_reply(struct kunit *test, struct ceph_osd_request *req)
{
	struct ceph_osd_req_op *op = &req->r_ops[0];
	u32 len = op->extent.length;

	test_fill(test, op->extent.osd_data.pages, 0, op->extent.offset, len);
	test_reply(test, req, 0, NULL, &len, NULL);
}

/* Fail the sub-reads of cancelled split reads that are still out. */
static void test_drain(struct kunit *test, struct ceph_osd_client *osdc)
{
	int i;

	for (i = 0; i < 64; i++) {
		struct ceph_osd_request *req = NULL;
		struct rb_node *n, *m;

		down_read(&osdc->lock);
		for (n = rb_first(&osdc->osds); n && !req; n = rb_next(n)) {
			struct ceph_osd *osd = rb_entry(n, struct ceph_osd,
							o_node);

			for (m = rb_first(&osd->o_requests); m && !req;
			     m = rb_next(m)) {
				req = rb_entry(m, struct ceph_osd_request,
					       r_node);
				if (req->r_callback != ec_split_sub_cb)
					req = NULL;
			}
		}
		if (req)
			ceph_osdc_get_request(req);
		up_read(&osdc->lock);
		if (!req)
			return;

		test_reply(test, req, -EIO, NULL, NULL, NULL);
		ceph_osdc_put_request(req);
	}
	KUNIT_FAIL(test, "sub-reads left in flight");
}

/*
 * Done with @req, whether or not it completed: cancelled, and a split
 * read's sub-reads answered before the reference goes.
 */
static void test_put(struct kunit *test, struct ceph_osd_request *req)
{
	ceph_osdc_cancel_request(req);
	test_drain(test, req->r_osdc);
	ceph_osdc_put_request(req);
}

/*
 * As in Objecter (pg_pool_t::allows_nonprimary_reads()), no direct reads
 * from a pool that is a tier, has tiers or has a dedup tier.
 */
static void direct_read_tier_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	int i;

	for (i = 0; i < 3; i++) {
		tm->pools[1].tier_of = i == 0 ? TEST_POOL_REP : 0;
		tm->pools[1].tier = i == 1 ? TEST_POOL_DST : 0;
		tm->pools[1].dedup_tier = i == 2 ? TEST_POOL_DST : 0;
		test_apply_map(test, osdc, tm);

		test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
		req = test_read(test, osdc, TEST_POOL_EC, "obj",
				CEPH_OSD_OP_READ, TEST_CHUNK, 1000,
				CEPH_OSD_FLAG_BALANCE_READS);
		ceph_osdc_start_request(osdc, req);
		KUNIT_EXPECT_EQ_MSG(test, test_osd(req), acting.primary,
				    "case %d", i);
		KUNIT_EXPECT_FALSE(test,
				   req->r_flags & CEPH_OSD_FLAG_EC_DIRECT_READ);
		test_put(test, req);
	}
}

/* Direct reads go to the shard's OSD, everything else to the primary. */
static void direct_read_target_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	int shard;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	for (shard = 0; shard < 2; shard++) {
		req = test_read(test, osdc, TEST_POOL_EC, "obj",
				CEPH_OSD_OP_READ, shard * TEST_CHUNK + 100,
				1000, CEPH_OSD_FLAG_BALANCE_READS);
		ceph_osdc_start_request(osdc, req);
		KUNIT_EXPECT_EQ(test, test_osd(req), acting.osds[shard]);
		KUNIT_EXPECT_EQ(test, req->r_t.spgid.shard, shard);
		KUNIT_EXPECT_TRUE(test, req->r_flags &
					CEPH_OSD_FLAG_EC_DIRECT_READ);
		test_read_reply(test, req);
		KUNIT_EXPECT_EQ(test, req->r_result, 1000);
		test_check_data(test, test_pages(req, 0),
				shard * TEST_CHUNK + 100, 1000);
		test_put(test, req);
	}

	/* without read_from_replica: the primary */
	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			TEST_CHUNK, 1000, 0);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	KUNIT_EXPECT_FALSE(test, req->r_flags & CEPH_OSD_FLAG_EC_DIRECT_READ);
	test_put(test, req);

	/* a shard with no OSD: the primary */
	tm->down = BIT(acting.osds[1]);
	test_apply_map(test, osdc, tm);
	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	KUNIT_ASSERT_EQ(test, acting.osds[1], CRUSH_ITEM_NONE);
	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			TEST_CHUNK, 1000, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	KUNIT_EXPECT_FALSE(test, req->r_flags & CEPH_OSD_FLAG_EC_DIRECT_READ);
	test_put(test, req);
}

/*
 * F2: a localized read of a pool over zones reads in the client's zone
 * only: with the shard's OSD there missing, it goes to the primary, not to
 * the shard's copy in the other zone.
 */
static void localize_zone_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_options *opt = osdc->client->options;
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	char loc[] = "datacenter:dc1";
	int local;

	KUNIT_ASSERT_EQ(test, ceph_parse_crush_location(loc, &opt->crush_locs),
			0);
	test_acting(osdc, TEST_POOL_EC_ZONES, "obj", &pgid, &acting);
	local = acting.osds[0] >= 6 ? 0 : 3;	/* dc1 holds osd.6..11 */

	req = test_read(test, osdc, TEST_POOL_EC_ZONES, "obj",
			CEPH_OSD_OP_READ, TEST_CHUNK, 1000,
			CEPH_OSD_FLAG_LOCALIZE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.osds[local + 1]);
	KUNIT_EXPECT_TRUE(test, req->r_flags & CEPH_OSD_FLAG_EC_DIRECT_READ);
	test_put(test, req);

	/* split: every shard from the local zone */
	req = test_read(test, osdc, TEST_POOL_EC_ZONES, "obj",
			CEPH_OSD_OP_READ, 0, 2 * TEST_CHUNK,
			CEPH_OSD_FLAG_LOCALIZE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_ASSERT_NOT_NULL(test, req->r_ec_split);
	KUNIT_EXPECT_EQ(test, test_osd(req->r_ec_split->subs[0].req),
			acting.osds[local]);
	KUNIT_EXPECT_EQ(test, test_osd(req->r_ec_split->subs[1].req),
			acting.osds[local + 1]);
	test_put(test, req);

	/* the local copy of shard 1 down: the primary, not the other zone */
	tm->down = BIT(acting.osds[local + 1]);
	test_apply_map(test, osdc, tm);
	test_acting(osdc, TEST_POOL_EC_ZONES, "obj", &pgid, &acting);
	KUNIT_ASSERT_EQ(test, acting.osds[local + 1], CRUSH_ITEM_NONE);
	req = test_read(test, osdc, TEST_POOL_EC_ZONES, "obj",
			CEPH_OSD_OP_READ, TEST_CHUNK, 1000,
			CEPH_OSD_FLAG_LOCALIZE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	KUNIT_EXPECT_FALSE(test, req->r_flags & CEPH_OSD_FLAG_EC_DIRECT_READ);
	test_put(test, req);

	/* and a split read that needs it goes to the primary too */
	req = test_read(test, osdc, TEST_POOL_EC_ZONES, "obj",
			CEPH_OSD_OP_READ, 0, 2 * TEST_CHUNK,
			CEPH_OSD_FLAG_LOCALIZE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_NULL(test, req->r_ec_split);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	test_put(test, req);
}

/* Balanced reads of a pool over zones use both zones. */
static void balance_zones_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	bool seen[2] = {};
	int i;

	test_acting(osdc, TEST_POOL_EC_ZONES, "obj", &pgid, &acting);
	for (i = 0; i < 64 && !(seen[0] && seen[1]); i++) {
		req = test_read(test, osdc, TEST_POOL_EC_ZONES, "obj",
				CEPH_OSD_OP_READ, TEST_CHUNK, 1000,
				CEPH_OSD_FLAG_BALANCE_READS);
		ceph_osdc_start_request(osdc, req);
		if (test_osd(req) == acting.osds[1])
			seen[0] = true;
		else if (test_osd(req) == acting.osds[4])
			seen[1] = true;
		else
			KUNIT_FAIL(test, "read of shard 1 sent to osd%d",
				   test_osd(req));
		test_put(test, req);
	}
	KUNIT_EXPECT_TRUE(test, seen[0] && seen[1]);
}

/*
 * F3: a single-chunk direct read whose PG changes goes to the primary, as
 * Objecter redrives it, rather than to a newly chosen shard.
 */
static void direct_read_pg_change_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			TEST_CHUNK, 1000, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_ASSERT_EQ(test, test_osd(req), acting.osds[1]);

	/* the parity shard's OSD goes down; shard 1's stays */
	tm->down = BIT(acting.osds[2]);
	test_apply_map(test, osdc, tm);
	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	KUNIT_EXPECT_EQ(test, req->r_attempts, 2);
	KUNIT_EXPECT_FALSE(test, req->r_flags &
				 (CEPH_OSD_FLAG_EC_DIRECT_READ |
				  CEPH_OSD_FLAG_BALANCE_READS));
	test_read_reply(test, req);
	KUNIT_EXPECT_EQ(test, req->r_result, 1000);
	test_put(test, req);
}

/*
 * A direct read is resent when its PG starts a new interval although its
 * OSD stays: the shard's OSD drops a direct read of an earlier interval
 * (PG::can_discard_op()).  Before, only linger requests were checked.
 */
static void test_interval_resend(struct kunit *test, const char *what,
				 void (*change)(struct test_osdmap *tm,
						u32 seed))
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			TEST_CHUNK, 1000, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_ASSERT_EQ(test, test_osd(req), acting.osds[1]);

	change(tm, pgid.seed);
	test_apply_map(test, osdc, tm);
	KUNIT_EXPECT_EQ_MSG(test, req->r_attempts, 2, "%s", what);
	KUNIT_EXPECT_EQ_MSG(test, test_osd(req), acting.primary, "%s", what);
	test_put(test, req);
}

static void test_change_min_size(struct test_osdmap *tm, u32 seed)
{
	tm->pools[1].min_size = 3;
}

/* TEST_POOL_EC starts migrating to TEST_POOL_DST, PG @seed first */
static void test_change_pg_migrating(struct test_osdmap *tm, u32 seed)
{
	tm->pools[1].migration_target = TEST_POOL_DST;
	tm->pools[1].num_migrating_pgs = 1;
	tm->pools[1].migrating_pgs[0] = seed;
	tm->pools[3].migration_src = TEST_POOL_EC;
	tm->pools[3].migration_root = TEST_POOL_EC;
}

/* ... with another PG first */
static void test_change_pool_migrating(struct test_osdmap *tm, u32 seed)
{
	test_change_pg_migrating(tm, (seed + 1) % 8);
}

static void direct_read_interval_test(struct kunit *test)
{
	test_interval_resend(test, "min_size", test_change_min_size);
}

static void direct_read_migrating_test(struct kunit *test)
{
	test_interval_resend(test, "pg_migrating", test_change_pg_migrating);
	test_interval_resend(test, "pool_pgs_migrating",
			     test_change_pool_migrating);
}

/*
 * The sub-reads of a split read whose PG starts a new interval fail with
 * -EAGAIN, as one-shot requests, and the read goes to the primary.  Before,
 * they waited for replies that the shards would never send.
 */
static void split_read_interval_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ, 0,
			3 * TEST_CHUNK, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_ASSERT_NOT_NULL(test, req->r_ec_split);

	tm->pools[1].min_size = 3;
	test_apply_map(test, osdc, tm);
	flush_workqueue(osdc->completion_wq);
	KUNIT_EXPECT_NULL(test, req->r_ec_split);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	if (test_osd(req) == acting.primary) {
		test_read_reply(test, req);
		KUNIT_EXPECT_EQ(test, req->r_result, 3 * TEST_CHUNK);
		test_check_data(test, test_pages(req, 0), 0, 3 * TEST_CHUNK);
	}
	test_put(test, req);
}

/* The request that registers @lreq now, and its tid */
static u64 test_linger_tid(struct ceph_osd_linger_request *lreq)
{
	struct ceph_osd_request *req;
	u64 tid = 0;

	mutex_lock(&lreq->lock);
	req = list_first_entry_or_null(&lreq->osd_reqs,
				       struct ceph_osd_request,
				       r_private_item);
	if (req)
		tid = req->r_tid;
	mutex_unlock(&lreq->lock);
	return tid;
}

static struct ceph_osd_linger_request *
test_watch(struct kunit *test, struct ceph_osd_client *osdc, s64 pool,
	   const char *oid)
{
	struct ceph_osd_linger_request *lreq = linger_alloc(osdc);

	KUNIT_ASSERT_NOT_NULL(test, lreq);
	lreq->is_watch = true;
	ceph_oid_printf(&lreq->t.base_oid, "%s", oid);
	lreq->t.base_oloc.pool = pool;
	lreq->t.flags = CEPH_OSD_FLAG_WRITE;
	ktime_get_real_ts64(&lreq->mtime);
	linger_submit(lreq);
	return lreq;
}

static void test_unwatch(struct ceph_osd_linger_request *lreq)
{
	linger_cancel(lreq);
	linger_put(lreq);
}

/*
 * Enabling EC optimizations on a pool starts a new interval
 * (PastIntervals::is_new_interval()): watches are sent again.
 */
static void ec_optimizations_interval_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc;
	struct ceph_osd_linger_request *lreq;
	u64 tid;

	tm->pools[1].flags = 0;
	tm->pools[1].nonprimary_shards[0] = 0;
	osdc = test_osdc(test, tm);
	lreq = test_watch(test, osdc, TEST_POOL_EC, "obj");
	tid = test_linger_tid(lreq);
	KUNIT_ASSERT_NE(test, tid, 0);

	/* an unrelated change keeps it */
	tm->pools[0].min_size = 1;
	test_apply_map(test, osdc, tm);
	KUNIT_EXPECT_EQ(test, test_linger_tid(lreq), tid);

	tm->pools[1].flags = CEPH_POOL_FLAG_EC_OPTIMIZATIONS;
	test_apply_map(test, osdc, tm);
	KUNIT_EXPECT_GT(test, test_linger_tid(lreq), tid);
	test_unwatch(lreq);
}

/* Sub-read @i's bytes of the read into its buffer: its length. */
static u32 test_fill_sub(struct kunit *test, struct ceph_ec_split *sp, int i)
{
	struct ceph_osd_req_op *op = &sp->req->r_ops[0];
	struct page **pages = sp->subs[i].req->r_ops[0].extent.osd_data.pages;
	u64 off = op->extent.offset, end = off + op->extent.length, c, r;
	u32 n = 0, raw = 0;

	for (c = div_u64(off, sp->chunk); c * sp->chunk < end; c++) {
		r = c;
		raw = do_div(r, sp->k);
		if (sp->raw_sub[raw] == i)
			break;
	}
	for (c = div_u64(off, sp->chunk); c * sp->chunk < end; c++) {
		u64 s = max(off, c * sp->chunk);
		u64 e = min(end, (c + 1) * sp->chunk);

		r = c;
		if (do_div(r, sp->k) != raw)
			continue;
		test_fill(test, pages, n, s, e - s);
		n += e - s;
	}
	return n;
}

/*
 * Sub-read @i's reply: up to @max_len bytes of its data, and version 5 for
 * every shard but its own at 4 if it is @stale.
 */
static void test_sub_reply(struct kunit *test, struct ceph_ec_split *sp,
			   int i, int stale, u32 max_len)
{
	struct ec_split_sub *sub = &sp->subs[i];
	struct ceph_osd_request *sreq = sub->req;
	int last = sreq->r_num_ops - 1;
	int rvals[2] = {}, vers[6][3], s;
	u32 lens[2] = {};

	for (s = 0; s < 6; s++) {
		vers[s][0] = s;
		vers[s][1] = s == stale && s == sub->shard ? 4 : 5;
		vers[s][2] = 1;
	}
	if (sub->len)
		lens[0] = min(test_fill_sub(test, sp, i), max_len);
	test_set_versions(test, sub, sub->shard, vers, 6, sp->v1);
	lens[last] = sreq->r_ops[last].outdata_len;
	test_reply(test, sreq, 0, rvals, lens, NULL);
}

/* Sub-read @i fails with @result, an op too if -EOPNOTSUPP. */
static void test_sub_error(struct kunit *test, struct ceph_ec_split *sp,
			   int i, int result)
{
	struct ceph_osd_request *sreq = sp->subs[i].req;
	int rvals[2] = {};

	if (result == -EOPNOTSUPP)
		rvals[sreq->r_num_ops - 1] = result;
	test_reply(test, sreq, result, rvals, NULL, NULL);
}

/* Every sub-read's reply, agreeing on the versions unless @stale. */
static void test_split_replies(struct kunit *test,
			       struct ceph_osd_request *req, int stale)
{
	struct ceph_ec_split *sp = req->r_ec_split;
	int i, n;

	KUNIT_ASSERT_NOT_NULL(test, sp);
	n = sp->num_subs;
	for (i = 0; i < n; i++)
		test_sub_reply(test, sp, i, stale, U32_MAX);
}

/* A read over chunks 0-3 of "obj": split between data shards 0 and 1 */
static struct ceph_osd_request *test_split_read(struct kunit *test,
						struct ceph_osd_client *osdc,
						int opcode)
{
	struct ceph_osd_request *req;

	req = test_read(test, osdc, TEST_POOL_EC, "obj", opcode, 100,
			3 * TEST_CHUNK, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_NOT_NULL(test, req->r_ec_split);
	return req;
}

static void split_read_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	int i;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	KUNIT_ASSERT_EQ(test, sp->num_subs, 2);
	for (i = 0; i < 2; i++) {
		struct ceph_osd_request *sreq = sp->subs[i].req;

		KUNIT_EXPECT_EQ(test, sp->subs[i].shard, i);
		KUNIT_EXPECT_EQ(test, sp->subs[i].len,
				ec_shard_bytes(100, 3 * TEST_CHUNK, TEST_CHUNK,
					       2, i));
		KUNIT_EXPECT_EQ(test, test_osd(sreq), acting.osds[i]);
		KUNIT_EXPECT_EQ(test, sreq->r_t.spgid.shard, i);
		KUNIT_EXPECT_TRUE(test, sreq->r_flags &
					CEPH_OSD_FLAG_FORCE_OSD);
		KUNIT_EXPECT_EQ(test, sreq->r_ops[1].op,
				CEPH_OSD_OP_GET_INTERNAL_VERSIONS_V2);
	}

	test_split_replies(test, req, -1);
	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	KUNIT_EXPECT_NULL(test, req->r_ec_split);
	KUNIT_EXPECT_EQ(test, req->r_result, 3 * TEST_CHUNK);
	KUNIT_EXPECT_EQ(test, req->r_ops[0].outdata_len, 3 * TEST_CHUNK);
	test_check_data(test, test_pages(req, 0), 100, 3 * TEST_CHUNK);
	test_put(test, req);
}

/*
 * A shard read before a write that the others saw: the read goes to the
 * primary.  With the split's sub-read count left at 0 (F6) the versions
 * were never compared.
 */
static void split_read_mismatch_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	test_split_replies(test, req, 1);
	KUNIT_EXPECT_FALSE(test, completion_done(&req->r_completion));
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	KUNIT_EXPECT_FALSE(test, req->r_flags & CEPH_OSD_FLAG_BALANCE_READS);
	if (test_osd(req) == acting.primary) {
		test_read_reply(test, req);
		KUNIT_EXPECT_EQ(test, req->r_result, 3 * TEST_CHUNK);
		test_check_data(test, test_pages(req, 0), 100,
				3 * TEST_CHUNK);
	}
	test_put(test, req);
}

/* Every shard without the object: -ENOENT without asking the primary */
static void split_read_enoent_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	test_sub_error(test, sp, 0, -ENOENT);
	test_sub_error(test, sp, 1, -ENOENT);
	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	KUNIT_EXPECT_EQ(test, req->r_result, -ENOENT);
	KUNIT_EXPECT_EQ(test, req->r_ops[0].rval, -ENOENT);
	test_put(test, req);
}

/* Sub-read @i's data if @result is 0, else its error */
static void test_sub_answer(struct kunit *test, struct ceph_ec_split *sp,
			    int i, int result)
{
	if (result)
		test_sub_error(test, sp, i, result);
	else
		test_sub_reply(test, sp, i, -1, U32_MAX);
}

/* One shard's error, -ENOENT among them, sends the read to the primary. */
static void split_read_error_test(struct kunit *test)
{
	static const int errs[][2] = {
		{ 0, -EAGAIN }, { -EIO, 0 }, { -ENOENT, 0 }, { 0, -EOVERFLOW },
	};
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osds acting;
	struct ceph_pg pgid;
	int i;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	for (i = 0; i < ARRAY_SIZE(errs); i++) {
		struct ceph_osd_request *req;
		struct ceph_ec_split *sp;

		req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
		sp = req->r_ec_split;
		KUNIT_ASSERT_NOT_NULL(test, sp);
		test_sub_answer(test, sp, 0, errs[i][0]);
		test_sub_answer(test, sp, 1, errs[i][1]);
		KUNIT_EXPECT_EQ_MSG(test, test_osd(req), acting.primary,
				    "errors %d %d", errs[i][0], errs[i][1]);
		if (test_osd(req) == acting.primary) {
			test_read_reply(test, req);
			KUNIT_EXPECT_EQ(test, req->r_result, 3 * TEST_CHUNK);
		}
		test_put(test, req);
	}
	KUNIT_EXPECT_FALSE(test, READ_ONCE(osdc->ec_split_v1));
}

/*
 * OSDs without GET_INTERNAL_VERSIONS_V2 (Umbrella) fail it with
 * -EOPNOTSUPP: that read goes to the primary, and the client uses
 * GET_INTERNAL_VERSIONS from then on, with the primary's versions as the
 * reference, read on their own if the primary holds none of the data.
 */
static void split_read_v1_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	int i;

	/* the parity shard's OSD is the primary */
	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	tm->num_primary_temp = 1;
	tm->primary_temp[0].pool = TEST_POOL_EC;
	tm->primary_temp[0].seed = pgid.seed;
	tm->primary_temp[0].osds[0] = acting.osds[2];
	test_apply_map(test, osdc, tm);
	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	KUNIT_ASSERT_EQ(test, acting.primary, acting.osds[2]);

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	test_sub_error(test, sp, 0, -EOPNOTSUPP);
	test_sub_error(test, sp, 1, -EOPNOTSUPP);
	KUNIT_EXPECT_TRUE(test, READ_ONCE(osdc->ec_split_v1));
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	if (test_osd(req) == acting.primary)
		test_read_reply(test, req);
	test_put(test, req);

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	KUNIT_EXPECT_TRUE(test, sp->v1);
	KUNIT_ASSERT_EQ(test, sp->num_subs, 3);
	KUNIT_EXPECT_EQ(test, sp->ref, 2);
	for (i = 0; i < 3; i++) {
		struct ceph_osd_request *sreq = sp->subs[i].req;

		KUNIT_EXPECT_EQ(test, sreq->r_ops[sreq->r_num_ops - 1].op,
				CEPH_OSD_OP_GET_INTERNAL_VERSIONS);
	}
	KUNIT_EXPECT_EQ(test, sp->subs[2].req->r_num_ops, 1);
	KUNIT_EXPECT_EQ(test, sp->subs[2].shard, 2);
	KUNIT_EXPECT_EQ(test, test_osd(sp->subs[2].req), acting.primary);
	test_split_replies(test, req, -1);
	KUNIT_EXPECT_EQ(test, req->r_result, 3 * TEST_CHUNK);
	test_check_data(test, test_pages(req, 0), 100, 3 * TEST_CHUNK);
	test_put(test, req);

	/* a shard behind the primary */
	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	if (req->r_ec_split) {
		test_split_replies(test, req, 1);
		KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	}
	test_put(test, req);
}

/*
 * Only GET_INTERNAL_VERSIONS_V2 failing with -EOPNOTSUPP shows an OSD
 * without it; the read op failing so leaves the client on V2.
 */
static void split_read_opnotsupp_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	int rvals[2] = { -EOPNOTSUPP };

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	test_reply(test, sp->subs[0].req, -EOPNOTSUPP, rvals, NULL, NULL);
	test_sub_error(test, sp, 1, -EIO);
	KUNIT_EXPECT_FALSE(test, osdc->ec_split_v1);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	test_put(test, req);
}

/*
 * Fail sub-read @i of @sp from the completion workqueue, as libceph fails
 * requests itself, while the caller holds osdc->lock for write as
 * ceph_osdc_cancel_request() does.  Give the completion time to go as far
 * as it can without osdc->lock.
 */
static void test_sub_fail_locked(struct ceph_ec_split *sp, int i, int err)
{
	struct ceph_osd_request *sreq = sp->subs[i].req;
	struct ceph_osd *osd = sreq->r_osd;
	struct ceph_osd_request *req = sp->req;

	verify_osdc_wrlocked(req->r_osdc);
	mutex_lock(&osd->lock);
	complete_request(sreq, err);
	mutex_unlock(&osd->lock);
	wait_for_completion_timeout(&req->r_completion, HZ / 2);
}

/*
 * A split read cancelled while its last sub-read fails: once
 * ceph_osdc_cancel_request() returns, the read must not go on to the
 * primary.
 */
static void split_read_cancel_fallback_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	test_sub_error(test, sp, 0, -EIO);

	down_write(&osdc->lock);
	test_sub_fail_locked(sp, 1, -EIO);
	if (req->r_osd)
		cancel_request(req);
	else if (req->r_ec_split)
		ec_split_cancel(req);
	up_write(&osdc->lock);
	flush_workqueue(osdc->completion_wq);

	KUNIT_EXPECT_EQ(test, test_osd(req), -1);
	test_put(test, req);
}

/*
 * A split read cancelled as its last sub-read completes it: between
 * ceph_osdc_cancel_request() finding the split and ec_split_cancel()
 * using it, the completion must not clear and free it.
 */
static void split_read_cancel_complete_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	test_sub_error(test, sp, 0, -ENOENT);

	down_write(&osdc->lock);
	KUNIT_EXPECT_PTR_EQ(test, req->r_ec_split, sp);
	test_sub_fail_locked(sp, 1, -ENOENT);
	KUNIT_EXPECT_PTR_EQ(test, req->r_ec_split, sp);
	if (req->r_ec_split == sp)
		ec_split_cancel(req);
	up_write(&osdc->lock);
	flush_workqueue(osdc->completion_wq);

	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	test_put(test, req);
}

static void test_count_cb(struct ceph_osd_request *req)
{
	(*(int *)req->r_priv)++;
}

/* A split read cancelled while its sub-reads are out. */
static void split_read_cancel_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;
	int calls = 0;

	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			100, 3 * TEST_CHUNK, CEPH_OSD_FLAG_BALANCE_READS);
	req->r_callback = test_count_cb;
	req->r_priv = &calls;
	ceph_osdc_start_request(osdc, req);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);

	test_sub_reply(test, sp, 0, -1, U32_MAX);
	ceph_osdc_cancel_request(req);
	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	KUNIT_EXPECT_NULL(test, req->r_ec_split);
	test_sub_reply(test, sp, 1, -1, U32_MAX);	/* the last frees it */
	KUNIT_EXPECT_EQ(test, calls, 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&osdc->num_requests), 0);
	ceph_osdc_put_request(req);
}

/*
 * F5: a split SPARSE_READ completes as one extent in the array the caller
 * allocated (CephFS does, for every sparse read), not in a new one.
 */
static void split_read_sparse_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_sparse_extent *ext;
	struct ceph_osd_req_op *op;
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;

	req = test_read(test, osdc, TEST_POOL_EC, "obj",
			CEPH_OSD_OP_SPARSE_READ, 100, 3 * TEST_CHUNK,
			CEPH_OSD_FLAG_BALANCE_READS);
	op = &req->r_ops[0];
	KUNIT_ASSERT_EQ(test, ceph_alloc_sparse_ext_map(op, 16), 0);
	ext = op->extent.sparse_ext;
	ceph_osdc_start_request(osdc, req);
	KUNIT_ASSERT_NOT_NULL(test, req->r_ec_split);

	test_split_replies(test, req, -1);
	KUNIT_EXPECT_EQ(test, req->r_result, 3 * TEST_CHUNK);
	KUNIT_EXPECT_EQ(test, op->rval, 0);
	KUNIT_EXPECT_PTR_EQ(test, op->extent.sparse_ext, ext);
	KUNIT_ASSERT_EQ(test, op->extent.sparse_ext_cnt, 1);
	KUNIT_EXPECT_EQ(test, op->extent.sparse_ext[0].off, 100);
	KUNIT_EXPECT_EQ(test, op->extent.sparse_ext[0].len, 3 * TEST_CHUNK);
	test_check_data(test, test_pages(req, 0), 100, 3 * TEST_CHUNK);
	test_put(test, req);

	/* the object ends in chunk 1: a shorter extent */
	req = test_read(test, osdc, TEST_POOL_EC, "obj",
			CEPH_OSD_OP_SPARSE_READ, 100, 3 * TEST_CHUNK,
			CEPH_OSD_FLAG_BALANCE_READS);
	op = &req->r_ops[0];
	KUNIT_ASSERT_EQ(test, ceph_alloc_sparse_ext_map(op, 16), 0);
	ext = op->extent.sparse_ext;
	ceph_osdc_start_request(osdc, req);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	test_sub_reply(test, sp, 0, -1, U32_MAX);
	test_sub_reply(test, sp, 1, -1, 1000);
	KUNIT_EXPECT_EQ(test, req->r_result, TEST_CHUNK - 100 + 1000);
	KUNIT_EXPECT_PTR_EQ(test, op->extent.sparse_ext, ext);
	KUNIT_EXPECT_EQ(test, op->extent.sparse_ext_cnt, 1);
	KUNIT_EXPECT_EQ(test, op->extent.sparse_ext[0].len,
			TEST_CHUNK - 100 + 1000);
	test_put(test, req);
}

/*
 * No split reads while the pool takes part in a migration: the object can
 * move to a pool with another layout before the sub-reads complete.
 * Single-chunk direct reads go on.
 */
static void split_read_migration_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc;
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;

	tm->pools[1].migration_target = TEST_POOL_DST;
	tm->pools[3].migration_src = TEST_POOL_EC;
	tm->pools[3].migration_root = TEST_POOL_EC;
	osdc = test_osdc(test, tm);
	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);

	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			100, 3 * TEST_CHUNK, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_NULL(test, req->r_ec_split);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	test_put(test, req);

	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			TEST_CHUNK, 1000, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.osds[1]);
	test_put(test, req);
}

/*
 * What F1 relies on: a read without the read_from_replica flags is never
 * direct or split, so its reply carries the object's version; a split read
 * has none.
 */
static void version_read_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;

	test_acting(osdc, TEST_POOL_EC, "obj", &pgid, &acting);
	req = test_read(test, osdc, TEST_POOL_EC, "obj", CEPH_OSD_OP_READ,
			100, 3 * TEST_CHUNK, 0);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_NULL(test, req->r_ec_split);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);
	test_read_reply(test, req);
	KUNIT_EXPECT_EQ(test, req->r_version, TEST_USER_VERSION);
	test_put(test, req);

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	test_split_replies(test, req, -1);
	KUNIT_EXPECT_EQ(test, req->r_version, 0);
	test_put(test, req);
}

/*
 * The reply to @req with @wire_len bytes of @wire as its data, received as
 * messenger v2 receives a reply with sparse reads
 * (process_v2_sparse_read()): the front first, then the data through
 * osd_sparse_read(), then the dispatch.
 */
static void test_receive(struct kunit *test, struct ceph_osd_request *req,
			 const u32 *lens, const void *wire, int wire_len)
{
	struct ceph_osd *osd = req->r_osd;
	struct ceph_msg_data_cursor cursor;
	struct ceph_msg_header hdr;
	struct ceph_msg *msg;
	int skip = 0, pos = 0, ret;

	KUNIT_ASSERT_NOT_NULL(test, osd);
	KUNIT_ASSERT_EQ(test, test_encode_reply(test, req, req->r_reply, 0,
						NULL, lens, NULL),
			wire_len);
	hdr = req->r_reply->hdr;
	msg = get_reply(&osd->o_con, &hdr, &skip);
	KUNIT_ASSERT_PTR_EQ(test, msg, req->r_reply);
	KUNIT_ASSERT_NE(test, msg->sparse_read_total, 0);

	osd->o_con.in_msg = msg;
	ceph_msg_data_cursor_init(&cursor, msg, msg->sparse_read_total);
	for (;;) {
		char *buf = NULL;

		ret = osd->o_con.ops->sparse_read(&osd->o_con, &cursor, &buf);
		if (ret <= 0 || pos + ret > wire_len)
			break;

		if (buf) {
			memcpy(buf, wire + pos, ret);
			pos += ret;
			continue;
		}
		while (ret) {
			size_t off, len;
			struct page *page = ceph_msg_data_next(&cursor, &off,
							       &len);

			len = min_t(size_t, len, ret);
			memcpy_to_page(page, off, wire + pos, len);
			ceph_msg_data_advance(&cursor, len);
			pos += len;
			ret -= len;
		}
	}
	osd->o_con.in_msg = NULL;
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, pos, wire_len);

	handle_reply(osd, msg);
	ceph_msg_put(msg);
}

/* A sparse read's reply data: extents @ext and their bytes of the objects */
static int test_sparse_wire(void *buf, const struct ceph_sparse_extent *ext,
			    int n)
{
	void *p = buf;
	u32 len = 0;
	int i;

	ceph_encode_32(&p, n);
	for (i = 0; i < n; i++) {
		ceph_encode_64(&p, ext[i].off);
		ceph_encode_64(&p, ext[i].len);
		len += ext[i].len;
	}
	ceph_encode_32(&p, len);
	for (i = 0; i < n; i++) {
		u64 j;

		for (j = 0; j < ext[i].len; j++)
			ceph_encode_8(&p, test_byte(ext[i].off + j));
	}
	return p - buf;
}

/* @pages hold extents @ext of the objects from @off, zeros in between. */
static void test_check_sparse(struct kunit *test, struct page **pages,
			      u64 off, const struct ceph_sparse_extent *ext,
			      int n)
{
	u64 end = ext[n - 1].off + ext[n - 1].len, pos;
	u8 *buf = kunit_kmalloc(test, end - off, GFP_KERNEL);
	int i = 0;

	KUNIT_ASSERT_NOT_NULL(test, buf);
	ceph_copy_from_page_vector(pages, buf, 0, end - off);
	for (pos = off; pos < end; pos++) {
		u8 want = 0;

		if (pos >= ext[i].off + ext[i].len)
			i++;
		if (pos >= ext[i].off)
			want = test_byte(pos);
		if (buf[pos - off] != want) {
			KUNIT_FAIL(test, "byte %llu is %02x, not %02x", pos,
				   buf[pos - off], want);
			break;
		}
	}
	kunit_kfree(test, buf);
}

/*
 * F4: a sparse read's extents and data, with holes zeroed.  The case for
 * plain ops of a multi-op reply sat between the data length state and the
 * data state that it runs on into, and took every sparse read with data.
 */
static void sparse_read_receive_test(struct kunit *test)
{
	static const struct ceph_sparse_extent ext[] = {
		{ TEST_CHUNK, TEST_CHUNK }, { 3 * TEST_CHUNK, 2048 },
	};
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	void *wire = kunit_kzalloc(test, 4 * TEST_CHUNK, GFP_KERNEL);
	struct ceph_osd_request *req;
	struct ceph_osd_req_op *op;
	u32 len;
	int i;

	KUNIT_ASSERT_NOT_NULL(test, wire);
	req = test_read(test, osdc, TEST_POOL_REP, "obj",
			CEPH_OSD_OP_SPARSE_READ, 0, 4 * TEST_CHUNK, 0);
	op = &req->r_ops[0];
	KUNIT_ASSERT_EQ(test, ceph_alloc_sparse_ext_map(op, 16), 0);
	ceph_osdc_start_request(osdc, req);

	len = test_sparse_wire(wire, ext, ARRAY_SIZE(ext));
	test_receive(test, req, &len, wire, len);
	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	KUNIT_EXPECT_EQ(test, req->r_result, len);
	KUNIT_ASSERT_EQ(test, op->extent.sparse_ext_cnt, ARRAY_SIZE(ext));
	for (i = 0; i < ARRAY_SIZE(ext); i++) {
		KUNIT_EXPECT_EQ(test, op->extent.sparse_ext[i].off, ext[i].off);
		KUNIT_EXPECT_EQ(test, op->extent.sparse_ext[i].len, ext[i].len);
	}
	test_check_sparse(test, test_pages(req, 0), 0, ext, ARRAY_SIZE(ext));
	test_put(test, req);

	/* no extents at all */
	req = test_read(test, osdc, TEST_POOL_REP, "obj",
			CEPH_OSD_OP_SPARSE_READ, 0, 4 * TEST_CHUNK, 0);
	op = &req->r_ops[0];
	KUNIT_ASSERT_EQ(test, ceph_alloc_sparse_ext_map(op, 16), 0);
	ceph_osdc_start_request(osdc, req);
	len = test_sparse_wire(wire, ext, 0);
	test_receive(test, req, &len, wire, len);
	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	KUNIT_EXPECT_EQ(test, op->extent.sparse_ext_cnt, 0);
	test_put(test, req);
}

/* A read and an op with a reply, as the sub-reads of split reads have. */
static struct ceph_osd_request *test_multi_read(struct kunit *test,
						struct ceph_osd_client *osdc,
						int opcode, u64 len)
{
	struct ceph_osd_request *req;
	struct page **pages;

	req = ceph_osdc_alloc_request(osdc, NULL, 2, false, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);
	ceph_oid_printf(&req->r_base_oid, "obj");
	req->r_base_oloc.pool = TEST_POOL_REP;
	req->r_flags = CEPH_OSD_FLAG_READ;
	req->r_multi_data = true;

	osd_req_op_extent_init(req, 0, opcode, 0, len, 0, 0);
	pages = ceph_alloc_page_vector(calc_pages_for(0, len), GFP_KERNEL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(pages));
	osd_req_op_extent_osd_data_pages(req, 0, pages, len, 0, false, true);
	if (opcode == CEPH_OSD_OP_SPARSE_READ)
		KUNIT_ASSERT_EQ(test,
				ceph_alloc_sparse_ext_map(&req->r_ops[0], 16),
				0);

	osd_req_op_init(req, 1, CEPH_OSD_OP_GET_INTERNAL_VERSIONS_V2, 0);
	pages = ceph_alloc_page_vector(1, GFP_KERNEL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(pages));
	osd_req_op_raw_data_in_pages(req, 1, pages, PAGE_SIZE, 0, false, true);
	KUNIT_ASSERT_EQ(test, ceph_osdc_alloc_messages(req, GFP_KERNEL), 0);

	ceph_osdc_start_request(osdc, req);
	return req;
}

/* @n bytes of the versions op's reply after @len bytes of @wire */
static void test_check_tail(struct kunit *test, struct ceph_osd_request *req,
			    const u8 *wire, int len, int n)
{
	u8 *buf = kunit_kmalloc(test, n, GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, buf);
	ceph_copy_from_page_vector(test_pages(req, 1), buf, 0, n);
	KUNIT_EXPECT_MEMEQ(test, buf, wire + len, n);
	kunit_kfree(test, buf);
}

/* A short read and the next op's data, each into its own buffer */
static void multi_data_receive_test(struct kunit *test)
{
	static const u32 reads[] = { 5000, 0, 2 * TEST_CHUNK };
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	u8 *wire = kunit_kzalloc(test, 4 * TEST_CHUNK, GFP_KERNEL);
	int i, j;

	KUNIT_ASSERT_NOT_NULL(test, wire);
	for (i = 0; i < ARRAY_SIZE(reads); i++) {
		struct ceph_osd_request *req;
		u32 lens[2] = { reads[i], 30 };

		for (j = 0; j < reads[i]; j++)
			wire[j] = test_byte(j);
		for (j = 0; j < 30; j++)
			wire[reads[i] + j] = 0xa0 + j;

		req = test_multi_read(test, osdc, CEPH_OSD_OP_READ,
				      2 * TEST_CHUNK);
		test_receive(test, req, lens, wire, lens[0] + lens[1]);
		KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
		KUNIT_EXPECT_EQ(test, req->r_ops[0].outdata_len, reads[i]);
		KUNIT_EXPECT_EQ(test, req->r_ops[1].outdata_len, 30);
		test_check_data(test, test_pages(req, 0), 0, reads[i]);
		test_check_tail(test, req, wire, reads[i], 30);
		test_put(test, req);
	}
}

/* A sparse read and a plain op in one reply (F4 again) */
static void sparse_plain_receive_test(struct kunit *test)
{
	static const struct ceph_sparse_extent ext[] = { { 1024, 1000 } };
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	u8 *wire = kunit_kzalloc(test, 4 * TEST_CHUNK, GFP_KERNEL);
	struct ceph_osd_request *req;
	u32 lens[2];
	int j;

	KUNIT_ASSERT_NOT_NULL(test, wire);
	lens[0] = test_sparse_wire(wire, ext, 1);
	lens[1] = 30;
	for (j = 0; j < 30; j++)
		wire[lens[0] + j] = 0xa0 + j;

	req = test_multi_read(test, osdc, CEPH_OSD_OP_SPARSE_READ,
			      2 * TEST_CHUNK);
	test_receive(test, req, lens, wire, lens[0] + lens[1]);
	KUNIT_EXPECT_TRUE(test, completion_done(&req->r_completion));
	KUNIT_ASSERT_EQ(test, req->r_ops[0].extent.sparse_ext_cnt, 1);
	KUNIT_EXPECT_EQ(test, req->r_ops[0].extent.sparse_ext[0].off, 1024);
	test_check_sparse(test, test_pages(req, 0), 0, ext, 1);
	test_check_tail(test, req, wire, lens[0], 30);
	test_put(test, req);
}

/* Objects o0, o1, ... in the PG of o0 of @pool, up to @n: how many. */
static int test_pg_objects(struct ceph_osd_client *osdc, s64 pool,
			   char (*names)[16], int n, u32 *seed)
{
	struct ceph_osds acting;
	struct ceph_pg pgid;
	char name[16];
	int i, found = 0;

	for (i = 0; i < 256 && found < n; i++) {
		snprintf(name, sizeof(name), "o%d", i);
		test_acting(osdc, pool, name, &pgid, &acting);
		if (!i)
			*seed = pgid.seed;
		if (pgid.seed == *seed)
			strscpy(names[found++], name, sizeof(names[0]));
	}
	return found;
}

/*
 * Four objects of a PG of TEST_POOL_REP that is migrating to
 * TEST_POOL_DST, in object order, and reads of them sent in another order.
 */
struct test_migration {
	struct kunit *test;
	struct ceph_osd_client *osdc;
	char names[4][16];
	struct ceph_osd_request_target t[4];
	struct ceph_hobject_id hoids[4];
	struct ceph_osd_request *reqs[4];
	u64 tids[4];
};

static void test_migration_done(void *arg)
{
	struct test_migration *tm = arg;
	int i;

	for (i = 0; i < 4; i++) {
		if (tm->reqs[i])
			test_put(tm->test, tm->reqs[i]);
		target_destroy(&tm->t[i]);
	}
}

/* Fill @tm's targets and object ids from its names. */
static void test_migration_hoids(struct test_migration *tm)
{
	struct ceph_pg_pool_info *pi;
	int i;

	pi = ceph_pg_pool_by_id(tm->osdc->osdmap, TEST_POOL_REP);
	for (i = 0; i < 4; i++) {
		struct ceph_osd_request_target *t = &tm->t[i];

		target_destroy(t);
		target_init(t);
		ceph_oid_printf(&t->target_oid, "%s", tm->names[i]);
		t->target_oloc.pool = TEST_POOL_REP;
		__ceph_object_locator_to_pg(pi, &t->target_oid,
					    &t->target_oloc, &t->pgid);
		hoid_fill_from_target(&tm->hoids[i], t);
	}
}

static struct test_migration *test_migration(struct kunit *test)
{
	static const int send_order[] = { 2, 0, 3, 1 };
	struct test_migration *tm = kunit_kzalloc(test, sizeof(*tm),
						  GFP_KERNEL);
	struct test_osdmap *map = ceph_kunit_osdmap_dup(test, &client_map);
	char names[4][16];
	int rank[4] = {};
	u32 seed;
	int i, j;

	KUNIT_ASSERT_NOT_NULL(test, tm);
	tm->test = test;
	tm->osdc = test_osdc(test, &client_map);
	KUNIT_ASSERT_EQ(test, test_pg_objects(tm->osdc, TEST_POOL_REP,
					      tm->names, 4, &seed), 4);
	for (i = 0; i < 4; i++)
		target_init(&tm->t[i]);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(test,
							test_migration_done,
							tm), 0);

	/* put the objects in order */
	test_migration_hoids(tm);
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 4; j++) {
			if (hoid_compare(&tm->hoids[j], &tm->hoids[i]) < 0)
				rank[i]++;
		}
	}
	memcpy(names, tm->names, sizeof(names));
	for (i = 0; i < 4; i++)
		strscpy(tm->names[rank[i]], names[i], sizeof(names[0]));
	test_migration_hoids(tm);

	map->pools[0].migration_target = TEST_POOL_DST;
	map->pools[0].num_migrating_pgs = 1;
	map->pools[0].migrating_pgs[0] = seed;
	map->pools[3].migration_src = TEST_POOL_REP;
	map->pools[3].migration_root = TEST_POOL_REP;
	test_apply_map(test, tm->osdc, map);

	for (i = 0; i < 4; i++) {
		int k = send_order[i];

		tm->reqs[k] = test_read(test, tm->osdc, TEST_POOL_REP,
					tm->names[k], CEPH_OSD_OP_READ, 0, 100,
					0);
		ceph_osdc_start_request(tm->osdc, tm->reqs[k]);
		tm->tids[k] = tm->reqs[k]->r_tid;
		KUNIT_ASSERT_EQ(test, tm->reqs[k]->r_t.target_oloc.pool,
				TEST_POOL_REP);
	}
	return tm;
}

/* The pool a new read of object @i of @tm goes to */
static s64 test_route_new(struct kunit *test, struct test_migration *tm,
			  int i)
{
	struct ceph_osd_request *req;
	s64 pool;

	req = test_read(test, tm->osdc, TEST_POOL_REP, tm->names[i],
			CEPH_OSD_OP_READ, 0, 100, 0);
	ceph_osdc_start_request(tm->osdc, req);
	pool = req->r_t.target_oloc.pool;
	test_put(test, req);
	return pool;
}

/*
 * A migration redirect moves the PG's watermark forward only, and resends
 * the requests for the objects it passed, and the redirected one, in the
 * order they were sent; the other requests stay.
 */
static void migration_redirect_test(struct kunit *test)
{
	struct test_migration *tm = test_migration(test);
	u64 max_tid = max(max(tm->tids[0], tm->tids[1]),
			  max(tm->tids[2], tm->tids[3]));

	/* objects 0 has migrated */
	test_reply(test, tm->reqs[0], 0, NULL, NULL, &tm->hoids[1]);
	KUNIT_EXPECT_EQ(test, tm->reqs[0]->r_t.target_oloc.pool,
			TEST_POOL_DST);
	KUNIT_EXPECT_GT(test, tm->reqs[0]->r_tid, max_tid);
	KUNIT_EXPECT_EQ(test, tm->reqs[1]->r_tid, tm->tids[1]);
	KUNIT_EXPECT_EQ(test, tm->reqs[2]->r_tid, tm->tids[2]);
	KUNIT_EXPECT_EQ(test, test_route_new(test, tm, 0), TEST_POOL_DST);
	KUNIT_EXPECT_EQ(test, test_route_new(test, tm, 1), TEST_POOL_REP);

	/* objects 1 and 2 too: object 2 was sent first */
	max_tid = tm->reqs[0]->r_tid;
	test_reply(test, tm->reqs[2], 0, NULL, NULL, &tm->hoids[3]);
	KUNIT_EXPECT_EQ(test, tm->reqs[1]->r_t.target_oloc.pool,
			TEST_POOL_DST);
	KUNIT_EXPECT_EQ(test, tm->reqs[2]->r_t.target_oloc.pool,
			TEST_POOL_DST);
	KUNIT_EXPECT_GT(test, tm->reqs[2]->r_tid, max_tid);
	KUNIT_EXPECT_GT(test, tm->reqs[1]->r_tid, tm->reqs[2]->r_tid);
	KUNIT_EXPECT_EQ(test, tm->reqs[3]->r_tid, tm->tids[3]);
	KUNIT_EXPECT_EQ(test, tm->reqs[3]->r_t.target_oloc.pool,
			TEST_POOL_REP);

	/* a late redirect with a lower watermark doesn't take it back */
	test_reply(test, tm->reqs[3], 0, NULL, NULL, &tm->hoids[1]);
	KUNIT_EXPECT_EQ(test, tm->reqs[3]->r_t.target_oloc.pool,
			TEST_POOL_REP);
	KUNIT_EXPECT_NE(test, tm->reqs[3]->r_tid, tm->tids[3]);
	KUNIT_EXPECT_EQ(test, test_route_new(test, tm, 2), TEST_POOL_DST);
	KUNIT_EXPECT_EQ(test, test_route_new(test, tm, 1), TEST_POOL_DST);
}

/* A copy of @hoid as a reply decodes it, for the client to own */
static struct ceph_hobject_id *test_hoid_dup(struct kunit *test,
					     const struct ceph_hobject_id *hoid)
{
	struct ceph_hobject_id *dup = kzalloc_obj(*dup, GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, dup);
	*dup = *hoid;
	dup->key = NULL;
	dup->key_len = 0;
	dup->nspace = NULL;
	dup->nspace_len = 0;
	dup->oid = kmemdup(hoid->oid, hoid->oid_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, dup->oid);
	return dup;
}

/*
 * Without memory to keep a PG's first watermark, the redirected request
 * fails with -ENOMEM rather than going back to the source to be
 * redirected again, and the other requests stay where they are.
 */
static void migration_wm_nomem_test(struct kunit *test)
{
	struct test_migration *tm = test_migration(test);
	struct ceph_osd_client *osdc = tm->osdc;
	struct ceph_osd_request *req = tm->reqs[0];
	struct ceph_hobject_id *wm = test_hoid_dup(test, &tm->hoids[1]);

	down_write(&osdc->lock);
	handle_migration_redirect(osdc, req->r_osd, &req->r_t.spgid.pgid, wm,
				  NULL, req->r_tid);
	up_write(&osdc->lock);
	flush_workqueue(osdc->completion_wq);

	KUNIT_EXPECT_EQ(test, req->r_result, -ENOMEM);
	KUNIT_EXPECT_EQ(test, tm->reqs[1]->r_tid, tm->tids[1]);
	KUNIT_EXPECT_EQ(test, tm->reqs[2]->r_tid, tm->tids[2]);
	KUNIT_EXPECT_EQ(test, test_route_new(test, tm, 0), TEST_POOL_REP);
}

/*
 * A PG merge in the pool that a finished migration sends requests to.  The
 * merge target is on the merge source's OSDs (pgp_num is reduced first),
 * which drop requests for the source, so the request moves only because
 * the monitors force a resend in that pool (last_force_op_resend_prenautilus).
 */
static void migration_merge_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc;
	struct ceph_osd_request *req;
	struct ceph_osds acting, merged;
	struct ceph_pg pgid;
	char name[16];
	int i;

	tm->pools[0].migration_target = TEST_POOL_DST;
	tm->pools[3].migration_root = TEST_POOL_REP;
	tm->pools[3].pgp_num = 4;
	osdc = test_osdc(test, tm);
	for (i = 0; i < 256; i++) {
		snprintf(name, sizeof(name), "o%d", i);
		test_acting(osdc, TEST_POOL_DST, name, &pgid, &acting);
		if (pgid.seed == 7)
			break;
	}
	KUNIT_ASSERT_LT(test, i, 256);
	req = test_read(test, osdc, TEST_POOL_REP, name, CEPH_OSD_OP_READ, 0,
			100, 0);
	ceph_osdc_start_request(osdc, req);
	KUNIT_ASSERT_EQ(test, req->r_t.target_oloc.pool, TEST_POOL_DST);
	KUNIT_ASSERT_EQ(test, req->r_t.spgid.pgid.seed, 7);

	/* PG 7 merges into PG 3 */
	tm->pools[3].pg_num = 7;
	tm->pools[3].last_force_resend = osdc->osdmap->epoch + 1;
	test_apply_map(test, osdc, tm);
	test_acting(osdc, TEST_POOL_DST, name, &pgid, &merged);
	KUNIT_ASSERT_EQ(test, pgid.seed, 3);
	KUNIT_ASSERT_EQ(test, merged.primary, acting.primary);
	KUNIT_EXPECT_EQ(test, req->r_attempts, 2);
	KUNIT_EXPECT_EQ(test, req->r_t.spgid.pgid.seed, 3);
	test_put(test, req);
}

/*
 * A watch cancelled while a pong completes its ping: handle_reply()
 * finishes the ping under the locks and completes it after dropping them,
 * and __linger_cancel() can take it off lreq->osd_reqs in between.  The
 * list's reference must then be dropped once, by __linger_cancel(), and
 * not again by linger_ping_cb() (KASAN: slab-use-after-free in
 * complete_all(), seen with rbd after OSD session resets).
 */
static void linger_ping_cancel_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_linger_request *lreq;
	struct ceph_osd_request *ping;
	struct ceph_osd *osd;
	unsigned int refs;

	lreq = test_watch(test, osdc, TEST_POOL_REP, "obj");

	down_write(&osdc->lock);
	send_linger_ping(lreq);
	ping = list_last_entry(&lreq->osd_reqs, struct ceph_osd_request,
			       r_private_item);
	KUNIT_ASSERT_TRUE(test, ping->r_callback == linger_ping_cb);
	/* two references of our own, so that a double put shows */
	ceph_osdc_get_request(ping);
	ceph_osdc_get_request(ping);

	/* handle_reply() takes the pong and finishes the ping... */
	osd = ping->r_osd;
	mutex_lock(&osd->lock);
	finish_request(ping);
	mutex_unlock(&osd->lock);
	/* ...and the watch is cancelled before it completes it */
	__linger_cancel(lreq);
	up_write(&osdc->lock);
	__complete_request(ping);

	refs = kref_read(&ping->r_kref);
	KUNIT_EXPECT_EQ(test, refs, 2);
	while (refs--)
		ceph_osdc_put_request(ping);
	linger_put(lreq);
}

/* Watches on the redirected OSD follow objects that have migrated. */
static void migration_linger_test(struct kunit *test)
{
	struct test_migration *tm = test_migration(test);
	struct ceph_osd_linger_request *lreq;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	u64 tid;

	lreq = test_watch(test, tm->osdc, TEST_POOL_REP, tm->names[0]);
	tid = test_linger_tid(lreq);
	KUNIT_EXPECT_EQ(test, lreq->t.target_oloc.pool, TEST_POOL_REP);

	test_reply(test, tm->reqs[1], 0, NULL, NULL, &tm->hoids[2]);
	test_acting(tm->osdc, TEST_POOL_DST, tm->names[0], &pgid, &acting);
	KUNIT_EXPECT_EQ(test, lreq->t.target_oloc.pool, TEST_POOL_DST);
	KUNIT_EXPECT_EQ(test, lreq->osd->o_osd, acting.primary);
	KUNIT_EXPECT_GT(test, test_linger_tid(lreq), tid);
	test_unwatch(lreq);
}

/*
 * A single-chunk direct read redirected to a replicated pool by a pool
 * migration goes to the primary there, as a plain read: OSDs fail EC
 * direct reads on pools without EC optimizations with -EOPNOTSUPP.
 */
static void direct_read_migration_redirect_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *reqs[2], *req;
	struct ceph_hobject_id hoids[2];
	struct ceph_osds acting;
	struct ceph_pg pgid;
	char names[2][16];
	u32 seed;
	int i;

	KUNIT_ASSERT_EQ(test, test_pg_objects(osdc, TEST_POOL_EC, names, 2,
					      &seed), 2);
	tm->pools[1].migration_target = TEST_POOL_DST;
	tm->pools[1].num_migrating_pgs = 1;
	tm->pools[1].migrating_pgs[0] = seed;
	tm->pools[3].migration_src = TEST_POOL_EC;
	tm->pools[3].migration_root = TEST_POOL_EC;
	test_apply_map(test, osdc, tm);

	test_acting(osdc, TEST_POOL_EC, names[0], &pgid, &acting);
	for (i = 0; i < 2; i++) {
		reqs[i] = test_read(test, osdc, TEST_POOL_EC, names[i],
				    CEPH_OSD_OP_READ, TEST_CHUNK, 1000,
				    CEPH_OSD_FLAG_BALANCE_READS);
		ceph_osdc_start_request(osdc, reqs[i]);
		KUNIT_ASSERT_EQ(test, test_osd(reqs[i]), acting.osds[1]);
		hoid_fill_from_target(&hoids[i], &reqs[i]->r_t);
	}

	/* the shard redirects the object that sorts first */
	i = hoid_compare(&hoids[0], &hoids[1]) > 0;
	req = reqs[i];
	test_reply(test, req, -ENOENT, NULL, NULL, &hoids[!i]);
	test_acting(osdc, TEST_POOL_DST, names[i], &pgid, &acting);
	KUNIT_EXPECT_EQ(test, req->r_t.target_oloc.pool, TEST_POOL_DST);
	KUNIT_EXPECT_FALSE(test, req->r_flags & CEPH_OSD_FLAG_EC_DIRECT_READ);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.primary);

	for (i = 0; i < 2; i++)
		test_put(test, reqs[i]);
}

/*
 * A split read cancelled and released by its owner while its sub-reads
 * are out, as ceph_osdc_wait_request() leaves one when interrupted: the
 * sub-reads complete without touching the parent (KASAN).
 */
static void split_read_cancel_release_test(struct kunit *test)
{
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_request *req;
	struct ceph_ec_split *sp;

	req = test_split_read(test, osdc, CEPH_OSD_OP_READ);
	sp = req->r_ec_split;
	KUNIT_ASSERT_NOT_NULL(test, sp);
	ceph_osdc_cancel_request(req);
	ceph_osdc_put_request(req);

	test_sub_error(test, sp, 0, -EIO);
	test_sub_error(test, sp, 1, -EIO);	/* the last finishes it */
	KUNIT_EXPECT_EQ(test, atomic_read(&osdc->num_requests), 0);
}

/* An object of @pool in a PG other than 0, and its PG */
static void test_pg_not_0(struct ceph_osd_client *osdc, s64 pool, char *name,
			  struct ceph_pg *pgid)
{
	struct ceph_osds acting;
	int i;

	for (i = 0; i < 64; i++) {
		snprintf(name, 16, "o%d", i);
		test_acting(osdc, pool, name, pgid, &acting);
		if (pgid->seed)
			return;
	}
}

/*
 * Whether the object's PG is migrating is kept for that PG, not for
 * last_pgid, which is PG 0 on a target's first calculation.  Otherwise,
 * with PG 0 not migrating and the object's PG migrating, a single-chunk
 * direct read would go to the primary as it is submitted (calc_target()
 * runs twice then), and a watch would be resent on an unrelated map change.
 */
static void pg_migrating_first_calc_test(struct kunit *test)
{
	struct test_osdmap *tm = ceph_kunit_osdmap_dup(test, &client_map);
	struct ceph_osd_client *osdc = test_osdc(test, &client_map);
	struct ceph_osd_linger_request *lreq;
	struct ceph_osd_request *req;
	struct ceph_osds acting;
	struct ceph_pg pgid;
	char rep[16], ec[16];
	u64 tid;

	test_pg_not_0(osdc, TEST_POOL_REP, rep, &pgid);
	KUNIT_ASSERT_NE(test, pgid.seed, 0);
	tm->pools[0].migration_target = TEST_POOL_DST;
	tm->pools[0].num_migrating_pgs = 1;
	tm->pools[0].migrating_pgs[0] = pgid.seed;
	tm->pools[3].migration_src = TEST_POOL_REP;
	tm->pools[3].migration_root = TEST_POOL_REP;
	test_pg_not_0(osdc, TEST_POOL_EC, ec, &pgid);
	KUNIT_ASSERT_NE(test, pgid.seed, 0);
	tm->pools[1].migration_target = TEST_POOL_EC_ZONES;
	tm->pools[1].num_migrating_pgs = 1;
	tm->pools[1].migrating_pgs[0] = pgid.seed;
	tm->pools[2].migration_src = TEST_POOL_EC;
	tm->pools[2].migration_root = TEST_POOL_EC;
	test_apply_map(test, osdc, tm);

	test_acting(osdc, TEST_POOL_EC, ec, &pgid, &acting);
	req = test_read(test, osdc, TEST_POOL_EC, ec, CEPH_OSD_OP_READ,
			TEST_CHUNK, 1000, CEPH_OSD_FLAG_BALANCE_READS);
	ceph_osdc_start_request(osdc, req);
	KUNIT_EXPECT_EQ(test, test_osd(req), acting.osds[1]);
	test_put(test, req);

	lreq = test_watch(test, osdc, TEST_POOL_REP, rep);
	tid = test_linger_tid(lreq);
	tm->pools[3].min_size = 1;		/* an unrelated change */
	test_apply_map(test, osdc, tm);
	KUNIT_EXPECT_EQ(test, test_linger_tid(lreq), tid);
	test_unwatch(lreq);
}

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

static struct kunit_case ceph_osd_client_target_test_cases[] = {
	KUNIT_CASE(direct_read_target_test),
	KUNIT_CASE(direct_read_tier_test),
	KUNIT_CASE(localize_zone_test),
	KUNIT_CASE(balance_zones_test),
	KUNIT_CASE(direct_read_pg_change_test),
	KUNIT_CASE(direct_read_interval_test),
	KUNIT_CASE(direct_read_migrating_test),
	KUNIT_CASE(split_read_interval_test),
	KUNIT_CASE(ec_optimizations_interval_test),
	{}
};

static struct kunit_suite ceph_osd_client_target_test_suite = {
	.name = "ceph_osd_client_target",
	.test_cases = ceph_osd_client_target_test_cases,
};

static struct kunit_case ceph_osd_client_split_test_cases[] = {
	KUNIT_CASE(split_read_test),
	KUNIT_CASE(split_read_mismatch_test),
	KUNIT_CASE(split_read_enoent_test),
	KUNIT_CASE(split_read_error_test),
	KUNIT_CASE(split_read_v1_test),
	KUNIT_CASE(split_read_cancel_test),
	KUNIT_CASE(split_read_sparse_test),
	KUNIT_CASE(split_read_migration_test),
	KUNIT_CASE(version_read_test),
	KUNIT_CASE(split_read_cancel_release_test),
	KUNIT_CASE(split_read_opnotsupp_test),
	KUNIT_CASE(split_read_cancel_fallback_test),
	KUNIT_CASE(split_read_cancel_complete_test),
	{}
};

static struct kunit_suite ceph_osd_client_split_test_suite = {
	.name = "ceph_osd_client_split",
	.test_cases = ceph_osd_client_split_test_cases,
};

static struct kunit_case ceph_osd_client_reply_test_cases[] = {
	KUNIT_CASE(sparse_read_receive_test),
	KUNIT_CASE(multi_data_receive_test),
	KUNIT_CASE(sparse_plain_receive_test),
	{}
};

static struct kunit_suite ceph_osd_client_reply_test_suite = {
	.name = "ceph_osd_client_reply",
	.test_cases = ceph_osd_client_reply_test_cases,
};

static struct kunit_case ceph_osd_client_migration_test_cases[] = {
	KUNIT_CASE(migration_redirect_test),
	KUNIT_CASE(migration_wm_nomem_test),
	KUNIT_CASE(migration_linger_test),
	KUNIT_CASE(linger_ping_cancel_test),
	KUNIT_CASE(direct_read_migration_redirect_test),
	KUNIT_CASE(pg_migrating_first_calc_test),
	KUNIT_CASE(migration_merge_test),
	{}
};

static struct kunit_suite ceph_osd_client_migration_test_suite = {
	.name = "ceph_osd_client_migration",
	.test_cases = ceph_osd_client_migration_test_cases,
};

kunit_test_suites(&ceph_osd_client_test_suite,
		  &ceph_osd_client_target_test_suite,
		  &ceph_osd_client_split_test_suite,
		  &ceph_osd_client_reply_test_suite,
		  &ceph_osd_client_migration_test_suite);
