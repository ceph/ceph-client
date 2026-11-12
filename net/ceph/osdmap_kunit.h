/* SPDX-License-Identifier: GPL-2.0 */
/*
 * OSD maps for the libceph KUnit tests, encoded as the monitors encode them
 * and decoded with ceph_osdmap_decode().  The CRUSH map has two datacenters,
 * dc0 and dc1, of three hosts each: host0..host2 hold osd.0..osd.5 and
 * host3..host5 hold osd.6..osd.11, two per host.
 */
#ifndef _NET_CEPH_OSDMAP_KUNIT_H
#define _NET_CEPH_OSDMAP_KUNIT_H

#include <kunit/test.h>
#include <linux/ceph/osdmap.h>

#define TEST_MAX_OSD		12
#define TEST_OSDMAP_BUF_LEN	16384
#define TEST_RULE_REP		0	/* chooseleaf firstn 0 host */
#define TEST_RULE_EC		1	/* chooseleaf indep 0 host */
#define TEST_RULE_EC_ZONES	2	/* 2 datacenters, 3 hosts in each */

struct test_pool {
	s64 id;				/* 1 if 0 */
	u8 v;
	u8 type;
	u8 size;
	u8 min_size;			/* size - 1 if 0 */
	u8 crush_rule;
	u32 pg_num;
	u32 pgp_num;			/* pg_num if 0 */
	u64 flags;
	u32 stripe_width;
	u64 nonprimary_shards[2];
	u32 shard_mapping_len;
	s8 shard_mapping[40];
	int ec_data_shard_count;	/* -1 if not set */
	s64 migration_src;
	s64 migration_target;
	s64 migration_root;
	u32 num_migrating_pgs;
	u32 migrating_pgs[4];
	u32 lowest_migrated_pg;
	u8 num_zones;
	s64 tier_of;			/* none if 0 */
	s64 tier;			/* the one entry of tiers if not 0 */
	s64 dedup_tier;			/* in opts if not 0 */
	u32 last_force_resend;		/* last_force_op_resend_prenautilus */
};

/* pg_temp, or primary_temp and pg_upmap_primaries in osds[0] */
struct test_pg_mapping {
	s64 pool;
	u32 seed;
	int len;
	int osds[8];
};

struct test_osdmap {
	u32 epoch;
	u32 flags;			/* CEPH_OSDMAP_* */
	unsigned long down;		/* OSDs that are not up */
	unsigned long out;		/* OSDs that are out */
	int num_pools;
	struct test_pool pools[4];
	int num_pg_temp;
	struct test_pg_mapping pg_temp[4];
	int num_primary_temp;
	struct test_pg_mapping primary_temp[4];
	int num_upmap_primaries;
	struct test_pg_mapping upmap_primaries[4];
	u8 rule_max_size;		/* of every rule, 100 if 0 */
};

size_t ceph_kunit_encode_osdmap(void *buf, const struct test_osdmap *tm);
struct ceph_osdmap *ceph_kunit_osdmap(struct kunit *test,
				      const struct test_osdmap *tm);
struct test_osdmap *ceph_kunit_osdmap_dup(struct kunit *test,
					  const struct test_osdmap *tm);

#endif
