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
    if (!pf->pages)
        return -ENOMEM;

    pf->buffer = page_address(pf->pages);
    pf->head = 0;
    pf->tail = 0;
    pf->active_elements = 0;
    pf->alloc_count = 0;
    pf->wrap_to_end = 0;
    pf->wrap_around = 0;
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
    pf->tail = 0;
    pf->active_elements = 0;
    pf->alloc_count = 0;
    pf->wrap_to_end = 0;
    pf->wrap_around = 0;
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
    int delta = CEPHSAN_PAGEFRAG_SIZE - pf->head -n;
    unsigned int prev_head = pf->head;

    /* Case 1: tail > head */
    if (pf->tail > pf->head) {
        if (pf->tail - pf->head > n) {
            pf->head += n;
            pf->alloc_count++;
            pf->active_elements++;
            return ((u64)n << 32) | prev_head;
        } else {
            return 0;
        }
    }
    /* Case 2: tail <= head */
    if (delta >= 0) {
        /* Normal allocation */
        /* make sure we have enough space to allocate next entry */
        pf->alloc_count++;
        pf->active_elements++;
        if (unlikely(delta < 64)) {
            n += delta;
            pf->head = 0;
            pf->wrap_to_end++;
            return ((u64)n << 32) | prev_head;
        }
        pf->head += n;
        return ((u64)n << 32) | prev_head;
    } else {
        if (pf->tail > n) {
            /* Need to wrap around return a partial allocation*/
            pf->head = n;
            pf->alloc_count++;
            pf->active_elements++;
            pf->wrap_around++;
            return ((u64)(delta + n) << 32) | prev_head;
        } else {
            return 0;
        }
    }
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

u64 cephsan_pagefrag_get_alloc_size(u64 val)
{
    return val >> 32;
}
EXPORT_SYMBOL(cephsan_pagefrag_get_alloc_size);

/**
 * cephsan_pagefrag_is_wraparound - Check if allocation wraps around buffer end
 * @val: Return value from cephsan_pagefrag_alloc
 *
 * Checks if the allocation represented by @val wraps around the end of the
 * pagefrag buffer by verifying if alloc_size + address > CEPHSAN_PAGEFRAG_SIZE.
 *
 * Return: true if allocation wraps around, false otherwise
 */
bool cephsan_pagefrag_is_wraparound(u64 val)
{
    u32 addr = val & 0xFFFFFFFF;
    u32 size = val >> 32;
    return (addr + size) > CEPHSAN_PAGEFRAG_SIZE;
}
EXPORT_SYMBOL(cephsan_pagefrag_is_wraparound);

/**
 * cephsan_pagefrag_get_ptr_from_tail - Get buffer pointer from pagefrag tail
 * @pf: pagefrag allocator
 * @n: number of bytes to get pointer from
 *
 * Returns pointer to the buffer region at the tail pointer minus @n bytes.
 */
void *cephsan_pagefrag_get_ptr_from_tail(struct cephsan_pagefrag *pf)
{
    return pf->buffer + pf->tail;
}
EXPORT_SYMBOL(cephsan_pagefrag_get_ptr_from_tail);

/**
 * cephsan_pagefrag_free - Free bytes in the pagefrag allocator.
 * @n: number of bytes to free.
 *
 * Advances the tail pointer by @n bytes (wrapping around if needed).
 */
void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n)
{
    pf->tail = (pf->tail + n) & (CEPHSAN_PAGEFRAG_SIZE - 1);
    pf->active_elements--;
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

/**
 * cephsan_pagefrag_reset - Reset the pagefrag allocator.
 *
 * Resets the head and tail pointers to the beginning of the buffer.
 */
void cephsan_pagefrag_reset(struct cephsan_pagefrag *pf)
{
    spin_lock(&pf->lock);
    pf->head = 0;
    pf->tail = 0;
    pf->alloc_count = 0;
    pf->active_elements = 0;
    pf->wrap_to_end = 0;
    pf->wrap_around = 0;
    spin_unlock(&pf->lock);
}
EXPORT_SYMBOL(cephsan_pagefrag_reset);
