// SPDX-License-Identifier: GPL-2.0
/*
 * BLOG page-fragment allocator.
 */

#include "blog_pagefrag.h"

/**
 * blog_pagefrag_reserve - reserve space without publishing it
 * @pf: pagefrag allocator
 * @n: number of bytes
 *
 * Returns the current head offset without advancing. Caller writes, then
 * blog_pagefrag_publish(). Single-writer (per-task).
 */
int blog_pagefrag_reserve(struct blog_pagefrag *pf, unsigned int n)
{
	if (n > pf->capacity - pf->head)
		return -ENOMEM;
	return pf->head;
}

/**
 * blog_pagefrag_publish - make reserved bytes visible to readers
 * @pf: pagefrag allocator
 * @publish_head: new head (offset + bytes_written)
 *
 * Store-release so a reader that observes the new head (load-acquire or
 * under pf->lock) sees the preceding entry writes. Single-writer.
 */
void blog_pagefrag_publish(struct blog_pagefrag *pf, unsigned int publish_head)
{
	/* Release-store pairs with the acquire in readers (pf->lock). */
	smp_store_release(&pf->head, publish_head);
}

void *blog_pagefrag_get_ptr(struct blog_pagefrag *pf, u64 val)
{
	char *base = (char *)pf->buffer;
	void *rc = base + val;

	if (unlikely(rc < pf->buffer ||
		     rc >= (void *)(base + pf->capacity))) {
		WARN_ON_ONCE(1);
		return NULL;
	}
	return rc;
}

/**
 * blog_pagefrag_reset - discard stored entries
 * @pf: pagefrag allocator to reset
 *
 * Callers must ensure no writer is mid-reservation. The pagefrag is
 * single-writer and writers do not take pf->lock.
 */
void blog_pagefrag_reset(struct blog_pagefrag *pf)
{
	spin_lock(&pf->lock);
	pf->head = 0;
	spin_unlock(&pf->lock);
}
