// SPDX-License-Identifier: GPL-2.0
/*
 * Binary Logging Page Fragment Management
 * 
 * Migrated from ceph_san_pagefrag.c with all algorithms preserved
 */

#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/blog/blog_pagefrag.h>

/**
 * blog_pagefrag_init - Initialize the pagefrag allocator.
 *
 * Allocates a 512KB contiguous buffer and resets head and tail pointers.
 *
 * Return: 0 on success, negative error code on failure.
 */
int blog_pagefrag_init(struct blog_pagefrag *pf)
{
	spin_lock_init(&pf->lock);
	pf->pages = alloc_pages(GFP_KERNEL, get_order(BLOG_PAGEFRAG_SIZE));
	if (!pf->pages) {
		pr_err("blog_pagefrag_init: alloc_pages failed\n");
		return -ENOMEM;
	}

	pf->buffer = page_address(pf->pages);
	pf->head = 0;
	pf->active_elements = 0;
	pf->alloc_count = 0;
	pf->last_entry = NULL;
	memset(pf->buffer, 0xc, BLOG_PAGEFRAG_SIZE);
	pr_debug("blog_pagefrag_init: buffer range %llx - %llx\n",
	         (unsigned long long)pf->buffer, (unsigned long long)pf->buffer + BLOG_PAGEFRAG_SIZE);
	return 0;
}
EXPORT_SYMBOL(blog_pagefrag_init);

/**
 * blog_pagefrag_init_with_buffer - Initialize pagefrag with an existing buffer
 * @pf: pagefrag allocator to initialize
 * @buffer: pre-allocated buffer to use
 * @size: size of the buffer
 *
 * Return: 0 on success
 */
int blog_pagefrag_init_with_buffer(struct blog_pagefrag *pf, void *buffer, size_t size)
{
	spin_lock_init(&pf->lock);
	pf->pages = NULL; /* No pages allocated, using provided buffer */
	pf->buffer = buffer;
	pf->head = 0;
	pf->active_elements = 0;
	pf->alloc_count = 0;
	pf->last_entry = NULL;
	return 0;
}
EXPORT_SYMBOL(blog_pagefrag_init_with_buffer);

/**
 * blog_pagefrag_alloc - Allocate bytes from the pagefrag buffer.
 * @n: number of bytes to allocate.
 *
 * Allocates @n bytes if there is sufficient free space in the buffer.
 * Advances the head pointer by @n bytes (wrapping around if needed).
 *
 * Return: offset to the allocated memory, or negative error if not enough space.
 */
int blog_pagefrag_alloc(struct blog_pagefrag *pf, unsigned int n)
{
	u64 offset;
	if (pf->head + n > BLOG_PAGEFRAG_SIZE) {
		return -ENOMEM; /* No space left */
	}
	offset = pf->head;
	pf->head += n;
	pf->alloc_count++;
	pf->active_elements++;
	return offset;
}
EXPORT_SYMBOL(blog_pagefrag_alloc);

/**
 * blog_pagefrag_get_ptr - Get buffer pointer from pagefrag allocation result
 * @pf: pagefrag allocator
 * @val: return value from blog_pagefrag_alloc
 *
 * Return: pointer to allocated buffer region
 */
void *blog_pagefrag_get_ptr(struct blog_pagefrag *pf, u64 val)
{
	void *rc = (void *)(pf->buffer + val);
	if (unlikely(pf->pages && pf->buffer != page_address(pf->pages))) {
		pr_err("blog_pagefrag_get_ptr: invalid buffer pointer %llx @ %s\n", 
		       (unsigned long long)pf->buffer, current->comm);
		BUG();
	}
	if (unlikely((rc) < pf->buffer || (rc) >= (pf->buffer + BLOG_PAGEFRAG_SIZE))) {
		pr_err("blog_pagefrag_get_ptr: invalid pointer %llx\n", (unsigned long long)rc);
		BUG();
	}
	return rc;
}
EXPORT_SYMBOL(blog_pagefrag_get_ptr);

/**
 * blog_pagefrag_get_ptr_from_tail - Get pointer from tail (not implemented in original)
 */
void *blog_pagefrag_get_ptr_from_tail(struct blog_pagefrag *pf)
{
	/* This function was not in the original ceph_san implementation */
	return NULL;
}
EXPORT_SYMBOL(blog_pagefrag_get_ptr_from_tail);

/**
 * blog_pagefrag_free - Free bytes from pagefrag (not implemented in original)
 */
void blog_pagefrag_free(struct blog_pagefrag *pf, unsigned int n)
{
	/* This function was not in the original ceph_san implementation */
}
EXPORT_SYMBOL(blog_pagefrag_free);

/**
 * blog_pagefrag_deinit - Deinitialize the pagefrag allocator.
 *
 * Frees the allocated buffer and resets the head and tail pointers.
 */
void blog_pagefrag_deinit(struct blog_pagefrag *pf)
{
	if (pf->pages) {
		__free_pages(pf->pages, get_order(BLOG_PAGEFRAG_SIZE));
		pf->pages = NULL;
	}
	/* Don't free buffer if it was provided externally */
	pf->buffer = NULL;
	pf->head = 0;
}
EXPORT_SYMBOL(blog_pagefrag_deinit);

/**
 * blog_pagefrag_reset - Reset the pagefrag allocator.
 *
 * Resets the head and tail pointers to the beginning of the buffer.
 */
void blog_pagefrag_reset(struct blog_pagefrag *pf)
{
	spin_lock(&pf->lock);
	pf->head = 0;
	pf->active_elements = 0;
	pf->alloc_count = 0;
	pf->last_entry = NULL;
	spin_unlock(&pf->lock);
}
EXPORT_SYMBOL(blog_pagefrag_reset);

/**
 * blog_pagefrag_trim_head - Trim bytes from head
 */
void blog_pagefrag_trim_head(struct blog_pagefrag *pf, unsigned int n)
{
	if (n > pf->head)
		pf->head = 0;
	else
		pf->head -= n;
}
EXPORT_SYMBOL(blog_pagefrag_trim_head);

/**
 * blog_pagefrag_trim - Trim bytes from pagefrag
 */
void blog_pagefrag_trim(struct blog_pagefrag *pf, unsigned int n)
{
	if (n >= pf->head) {
		pf->head = 0;
		pf->active_elements = 0;
		pf->alloc_count = 0;
		pf->last_entry = NULL;
	} else {
		pf->head -= n;
	}
}
EXPORT_SYMBOL(blog_pagefrag_trim);

/**
 * blog_pagefrag_is_wraparound - Check if allocation wrapped around
 */
bool blog_pagefrag_is_wraparound(u64 val)
{
	/* Not implemented in original - stub for now */
	return false;
}
EXPORT_SYMBOL(blog_pagefrag_is_wraparound);

/**
 * blog_pagefrag_get_alloc_size - Get allocation size from result
 */
u64 blog_pagefrag_get_alloc_size(u64 val)
{
	/* Not implemented in original - stub for now */
	return 0;
}
EXPORT_SYMBOL(blog_pagefrag_get_alloc_size);
