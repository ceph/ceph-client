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
    pf->pages = alloc_pages(GFP_KERNEL, get_order(CEPHSAN_PAGEFRAG_SIZE));
    if (!pf->pages)
        return -ENOMEM;

    pf->buffer = page_address(pf->pages);
    pf->head = 0;
    pf->tail = 0;
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
    pf->pages = NULL; /* No pages allocated, using provided buffer */
    pf->buffer = buffer;
    pf->head = 0;
    pf->tail = 0;
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
u64 cephsan_pagefrag_alloc(struct cephsan_pagefrag *pf, unsigned int n)
{
    /* Case 1: tail > head */
    if (pf->tail > pf->head) {
        if (pf->tail - pf->head >= n) {
            unsigned int prev_head = pf->head;
            pf->head += n;
            return ((u64)n << 32) | prev_head;
        } else {
            pr_err("Not enough space in pagefrag buffer\n");
            return 0;
        }
    }
    /* Case 2: tail <= head */
    if (pf->head + n <= CEPHSAN_PAGEFRAG_SIZE) {
        /* Normal allocation */
        unsigned int prev_head = pf->head;
        pf->head += n;
        return ((u64)n << 32) | prev_head;
    } else {
        /* Need to wrap around */
        if (n <= pf->tail) {
            pf->head = n;
            n += CEPHSAN_PAGEFRAG_SIZE - pf->head;
            return ((u64)n << 32) | 0;
        } else {
            pr_err("Not enough space for wrap-around allocation\n");
            return 0;
        }
    }
    pr_err("impossible: Not enough space in pagefrag buffer\n");
    return 0;
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
    return pf->buffer + (val & 0xFFFFFFFF);
}
EXPORT_SYMBOL(cephsan_pagefrag_get_ptr);

/**
 * cephsan_pagefrag_free - Free bytes in the pagefrag allocator.
 * @n: number of bytes to free.
 *
 * Advances the tail pointer by @n bytes (wrapping around if needed).
 */
void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n)
{
    pf->tail = (pf->tail + n) & (CEPHSAN_PAGEFRAG_SIZE - 1);
}
EXPORT_SYMBOL(cephsan_pagefrag_free);

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
    pf->head = pf->tail = 0;
}
EXPORT_SYMBOL(cephsan_pagefrag_deinit);
