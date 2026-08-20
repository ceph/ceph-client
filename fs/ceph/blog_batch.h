/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BLOG magazine batcher.
 */
#ifndef _FS_CEPH_BLOG_BATCH_H
#define _FS_CEPH_BLOG_BATCH_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#define BLOG_MAGAZINE_SIZE 16

struct blog_magazine {
	struct list_head list;
	unsigned int count;
	void *elements[BLOG_MAGAZINE_SIZE];
};

struct blog_cpu_magazine {
	struct blog_magazine *mag;
};

struct blog_batch {
	struct list_head full_magazines;
	struct list_head empty_magazines;
	raw_spinlock_t full_lock;
	raw_spinlock_t empty_lock;
	unsigned int nr_full;
	unsigned int nr_empty;
	struct blog_cpu_magazine __percpu *cpu_magazines;
	struct kmem_cache *magazine_cache;
	bool external_cache;
	unsigned int retain_limit;
};

int blog_batch_init(struct blog_batch *batch, struct kmem_cache *mag_cache,
		    unsigned int nr_prealloc, unsigned int retain_limit);
void blog_batch_cleanup(struct blog_batch *batch);
void *blog_batch_get(struct blog_batch *batch);
bool blog_batch_put(struct blog_batch *batch, void *element);

#endif /* _FS_CEPH_BLOG_BATCH_H */
