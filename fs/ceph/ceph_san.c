#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/ceph/ceph_san.h>

#ifdef CONFIG_DEBUG_FS
/* Global list and lock now hold TLS logger objects only */
LIST_HEAD(ceph_san_list);
DEFINE_SPINLOCK(ceph_san_lock);

/* The definitions for struct ceph_san_log_entry and struct ceph_san_tls_logger
 * have been moved to cephsan.h (under CONFIG_DEBUG_FS) to avoid duplication.
 */

char *get_log_cephsan(void) {
    struct ceph_san_tls_logger *tls;

    /* Check if the current task already has a TLS logger in its journal_info field.
     * (Note: This simplistic example assumes that current->journal_info is a valid field.)
     */
    if (current->journal_info) {
        tls = (struct ceph_san_tls_logger *)current->journal_info;
        if (tls->cephsun_sig != 0xD1E7C0CE) {
            pr_err("Ceph SAN: Invalid signature - %s(%d)\n", current->comm, current->pid);
            return NULL;
        }
        if (tls->task != current) {
            pr_err("Ceph SAN: Task mismatch - %s(%d)\n", current->comm, current->pid);
            return NULL;
        }
    } else {
        tls = kmalloc(sizeof(*tls), GFP_KERNEL);
        if (!tls) {
            pr_err("Ceph SAN: Failed to allocate TLS logger for %s(%d)\n", current->comm, current->pid);
            return NULL;
        }
        tls->cephsun_sig = 0xD1E7C0CE; /* example signature */
        tls->task = current;
        tls->head_idx = 0;
        tls->tail_idx = 0;
        INIT_LIST_HEAD(&tls->list);

        spin_lock(&ceph_san_lock);
        list_add_tail(&tls->list, &ceph_san_list);
        spin_unlock(&ceph_san_lock);

        /* Set current task's journal_info pointer to the newly allocated TLS logger */
        current->journal_info = (void *)tls;
    }

    if ((tls->head_idx + 1) % CEPH_SAN_MAX_LOGS == tls->tail_idx) {
        tls->tail_idx = (tls->tail_idx + 1) % CEPH_SAN_MAX_LOGS;
    }
    tls->logs[tls->head_idx].ts = jiffies;
    tls->head_idx = (tls->head_idx + 1) % CEPH_SAN_MAX_LOGS;
    return tls->logs[tls->head_idx].buf;
}
EXPORT_SYMBOL(get_log_cephsan);

/* Cleanup function to free all TLS logger objects.
 * Call this at module exit to free allocated TLS loggers.
 */
void cephsan_cleanup(void)
{
    struct ceph_san_tls_logger *tls, *tmp;

    spin_lock(&ceph_san_lock);
    list_for_each_entry_safe(tls, tmp, &ceph_san_list, list) {
         list_del(&tls->list);
         kfree(tls);
    }
    spin_unlock(&ceph_san_lock);
}
/* Initialize the Ceph SAN logging infrastructure.
 * Call this at module init to set up the global list and lock.
 */
int __init cephsan_init(void)
{
	spin_lock_init(&ceph_san_lock);
	INIT_LIST_HEAD(&ceph_san_list);
	return 0;
}

#endif /* CONFIG_DEBUG_FS */

/*
 * Pagefrag Allocator for ceph_san:
 *  - A contiguous 4-page buffer (16KB) is allocated.
 *  - The allocator maintains two unsigned int indices (head and tail) into the buffer.
 *  - cephsan_pagefrag_alloc(n) returns a pointer to n contiguous bytes (if available) and
 *    advances the head pointer by n bytes (wrapping around at the end).
 *  - cephsan_pagefrag_free(n) advances the tail pointer by n bytes.
 *
 * This simple ring-buffer allocator is intended for short-lived allocations in the Ceph SAN code.
 */

#define CEPHSAN_PAGEFRAG_SIZE  (4 * PAGE_SIZE)  /* 16KB */

/* Pagefrag allocator structure */
struct cephsan_pagefrag {
    void *buffer;
    unsigned int head;
    unsigned int tail;
};

/**
 * cephsan_pagefrag_init - Initialize the pagefrag allocator.
 *
 * Allocates a 16KB contiguous buffer and resets head and tail pointers.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int cephsan_pagefrag_init(struct cephsan_pagefrag *pf)
{
	pf->buffer = kmalloc(CEPHSAN_PAGEFRAG_SIZE, GFP_KERNEL);
	if (!pf->buffer)
		return -ENOMEM;

	pf->head = 0;
	pf->tail = 0;
	return 0;
}

/**
 * cephsan_pagefrag_alloc - Allocate bytes from the pagefrag buffer.
 * @n: number of bytes to allocate.
 *
 * Allocates @n bytes if there is sufficient free space in the buffer.
 * Advances the head pointer by @n bytes (wrapping around if needed).
 *
 * Return: pointer to the allocated memory, or NULL if not enough space.
 */
static u64 cephsan_pagefrag_alloc(struct cephsan_pagefrag *pf, unsigned int n)
{
	unsigned int used, free_space, remaining;
	void *ptr;

	/* Compute usage in the circular buffer */
	if (pf->head >= pf->tail)
		used = pf->head - pf->tail;
	else
		used = CEPHSAN_PAGEFRAG_SIZE - pf->tail + pf->head;

	free_space = CEPHSAN_PAGEFRAG_SIZE - used;
	if (n > free_space)
		return 0;

	/* Check if allocation would wrap around buffer end */
	if (pf->head + n > CEPHSAN_PAGEFRAG_SIZE) {
		/* Calculate bytes remaining until buffer end */
		remaining = CEPHSAN_PAGEFRAG_SIZE - pf->head;
		/* Move tail to start if needed */
		if (pf->tail < n - remaining)
			pf->tail = 0;

		/* Return pointer to new head at buffer start */
		ptr = pf->buffer;
		pf->head = n - remaining;
	} else {
		/* No wrap around needed */
		ptr = (char *)pf->buffer + pf->head;
		pf->head += n;
	}
	/* Return combined u64 with buffer index in lower 32 bits and size in upper 32 bits */
	return ((u64)(n) << 32) | (ptr - pf->buffer);
}

/**
 * cephsan_pagefrag_free - Free bytes in the pagefrag allocator.
 * @n: number of bytes to free.
 *
 * Advances the tail pointer by @n bytes (wrapping around if needed).
 */
static void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n)
{
	pf->tail = (pf->tail + n) % CEPHSAN_PAGEFRAG_SIZE;
}

/**
 * cephsan_pagefrag_deinit - Deinitialize the pagefrag allocator.
 *
 * Frees the allocated buffer and resets the head and tail pointers.
 */
static void cephsan_pagefrag_deinit(struct cephsan_pagefrag *pf)
{
	kfree(pf->buffer);
	pf->buffer = NULL;
	pf->head = pf->tail = 0;
}
