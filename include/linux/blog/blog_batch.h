/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Binary Logging Batch Management
 */
#ifndef _LINUX_BLOG_BATCH_H
#define _LINUX_BLOG_BATCH_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/* Size of each magazine (number of elements it can hold) */
#define BLOG_MAGAZINE_SIZE 16

/* Structure representing a single magazine */
struct blog_magazine {
	struct list_head list;      /* For linking in global pools */
	unsigned int count;         /* Number of elements currently in magazine */
	void *elements[BLOG_MAGAZINE_SIZE];
};

/* Per-CPU magazine state */
struct blog_cpu_magazine {
	struct blog_magazine *mag;  /* Current magazine for this CPU */
};

/* Global magazine pools */
struct blog_batch {
	struct list_head full_magazines;   /* List of full magazines */
	struct list_head empty_magazines;  /* List of empty magazines */
	spinlock_t full_lock;              /* Protects full magazine list and count */
	spinlock_t empty_lock;             /* Protects empty magazine list and count */
	unsigned int nr_full;              /* Protected by full_lock */
	unsigned int nr_empty;             /* Protected by empty_lock */
	struct blog_cpu_magazine __percpu *cpu_magazines; /* Per-CPU magazines */
	struct kmem_cache *magazine_cache; /* Cache for magazine allocations */
};

/* Initialize the batching system */
int blog_batch_init(struct blog_batch *batch);

/* Clean up the batching system */
void blog_batch_cleanup(struct blog_batch *batch);

/* Get an element from the batch */
void *blog_batch_get(struct blog_batch *batch);

/* Put an element back into the batch */
void blog_batch_put(struct blog_batch *batch, void *element);

#endif /* _LINUX_BLOG_BATCH_H */
