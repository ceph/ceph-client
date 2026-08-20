/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BLOG page-fragment allocator.
 */
#ifndef _FS_CEPH_BLOG_PAGEFRAG_H
#define _FS_CEPH_BLOG_PAGEFRAG_H

#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/spinlock.h>

#define BLOG_PAGEFRAG_SIZE  SZ_4K
#define BLOG_PAGEFRAG_MASK (BLOG_PAGEFRAG_SIZE - 1)

struct blog_pagefrag {
	void *buffer;
	size_t capacity;
	spinlock_t lock;
	unsigned int head;
};

int blog_pagefrag_reserve(struct blog_pagefrag *pf, unsigned int n);
void blog_pagefrag_publish(struct blog_pagefrag *pf, unsigned int publish_head);
void blog_pagefrag_reset(struct blog_pagefrag *pf);
void *blog_pagefrag_get_ptr(struct blog_pagefrag *pf, u64 val);

#endif /* _FS_CEPH_BLOG_PAGEFRAG_H */
