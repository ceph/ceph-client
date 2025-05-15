#include "linux/printk.h"
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/ceph/ceph_san_pagefrag.h>

/**
 * cephsan_pagefrag_init - Initialize the pagefrag allocator.
 *
 * Allocates a 4MB contiguous buffer and resets head and tail pointers.
 *
 * Return: 0 on success, negative error code on failure.
 */
int cephsan_pagefrag_init(struct cephsan_pagefrag *pf)
{
    spin_lock_init(&pf->lock);
    pf->pages = alloc_pages(GFP_KERNEL, get_order(CEPHSAN_PAGEFRAG_SIZE));
    if (!pf->pages) {
        pr_err("ceph_san_pagefrag_init: alloc_pages failed\n");
        return -ENOMEM;
    }

    pf->buffer = page_address(pf->pages);
    pf->head = 0;
    pf->active_elements = 0;
    pf->alloc_count = 0;
    pf->last_entry = NULL;
    memset(pf->buffer, 0xc, CEPHSAN_PAGEFRAG_SIZE);
    pr_debug("ceph_san_pagefrag_init: buffer range %llx - %llx\n",
             (unsigned long long)pf->buffer, (unsigned long long)pf->buffer + CEPHSAN_PAGEFRAG_SIZE);
    return 0;
}
EXPORT_SYMBOL(cephsan_pagefrag_init);

/**
 * cephsan_pagefrag_init_with_buffer - Initialize pagefrag with an existing buffer
 * @pf: pagefrag allocator to initialize
 * @buffer: pre-allocated buffer to use
 * @size: size of the buffer
 *
 * Return: 0 on success
 */
int cephsan_pagefrag_init_with_buffer(struct cephsan_pagefrag *pf, void *buffer, size_t size)
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
EXPORT_SYMBOL(cephsan_pagefrag_init_with_buffer);

/**
 * cephsan_pagefrag_alloc - Allocate bytes from the pagefrag buffer.
 * @n: number of bytes to allocate.
 *
 * Allocates @n bytes if there is sufficient free space in the buffer.
 * Advances the head pointer by @n bytes (wrapping around if needed).
 *
 * Return: pointer to the allocated memory, or NULL if not enough space.
 */
int cephsan_pagefrag_alloc(struct cephsan_pagefrag *pf, unsigned int n)
{
    u64 offset;
    if (pf->head + n > CEPHSAN_PAGEFRAG_SIZE) {
        return -ENOMEM; // No space left
    }
    offset = pf->head;
    pf->head += n;
    pf->alloc_count++;
    pf->active_elements++;
    return offset;
}
EXPORT_SYMBOL(cephsan_pagefrag_alloc);

/**
 * cephsan_pagefrag_get_ptr - Get buffer pointer from pagefrag allocation result
 * @pf: pagefrag allocator
 * @val: return value from cephsan_pagefrag_alloc
 *
 * Return: pointer to allocated buffer region
 */
void *cephsan_pagefrag_get_ptr(struct cephsan_pagefrag *pf, u64 val)
{
     void *rc = (void *)(pf->buffer + val);
     if (unlikely(pf->buffer != page_address(pf->pages))) {
        pr_err("ceph_san_pagefrag_get_ptr: invalid buffer pointer %llx @ %s\n", (unsigned long long)pf->buffer, current->comm);
        BUG();
     }
     if (unlikely((rc) < pf->buffer || (rc) >= (pf->buffer + CEPHSAN_PAGEFRAG_SIZE))) {
        pr_err("ceph_san_pagefrag_get_ptr: invalid pointer %llx\n", (unsigned long long)rc);
        BUG();
     }
     return rc;
}
EXPORT_SYMBOL(cephsan_pagefrag_get_ptr);

/**
 * cephsan_pagefrag_deinit - Deinitialize the pagefrag allocator.
 *
 * Frees the allocated buffer and resets the head and tail pointers.
 */
void cephsan_pagefrag_deinit(struct cephsan_pagefrag *pf)
{
    if (pf->pages) {
        free_pages((unsigned long)pf->pages, get_order(CEPHSAN_PAGEFRAG_SIZE));
        pf->pages = NULL;
    }
    /* Don't free buffer if it was provided externally */
    pf->buffer = NULL;
    pf->head = 0;
}
EXPORT_SYMBOL(cephsan_pagefrag_deinit);

/**
 * cephsan_pagefrag_reset - Reset the pagefrag allocator.
 *
 * Resets the head and tail pointers to the beginning of the buffer.
 */
void cephsan_pagefrag_reset(struct cephsan_pagefrag *pf)
{
    spin_lock(&pf->lock);
    pf->head = 0;
    pf->active_elements = 0;
    pf->alloc_count = 0;
    pf->last_entry = NULL;
    spin_unlock(&pf->lock);
}
EXPORT_SYMBOL(cephsan_pagefrag_reset);

void cephsan_pagefrag_trim_head(struct cephsan_pagefrag *pf, unsigned int n)
{
    if (n > pf->head)
        pf->head = 0;
    else
        pf->head -= n;
}
EXPORT_SYMBOL(cephsan_pagefrag_trim_head);

void cephsan_pagefrag_trim(struct cephsan_pagefrag *pf, unsigned int n)
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
EXPORT_SYMBOL(cephsan_pagefrag_trim);
