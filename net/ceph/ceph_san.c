#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/ceph/ceph_san.h>
#include <linux/mm.h>

/* Use per-core TLS logger; no global list or lock needed */
DEFINE_PER_CPU(struct ceph_san_tls_logger, ceph_san_tls);
EXPORT_SYMBOL(ceph_san_tls);
/* The definitions for struct ceph_san_log_entry and struct ceph_san_tls_logger
 * have been moved to cephsan.h (under CONFIG_DEBUG_FS) to avoid duplication.
 */

char *get_log_cephsan(void) {
    /* Use the per-core TLS logger */
    struct ceph_san_tls_logger *tls = this_cpu_ptr(&ceph_san_tls);
    int head_idx = tls->head_idx++ & (CEPH_SAN_MAX_LOGS - 1);
    tls->logs[head_idx].pid = current->pid;
    tls->logs[head_idx].ts = jiffies;
    memcpy(tls->logs[head_idx].comm, current->comm, TASK_COMM_LEN);

    return tls->logs[head_idx].buf;
}
EXPORT_SYMBOL(get_log_cephsan);

/* Cleanup function to free all TLS logger objects.
 * Call this at module exit to free allocated TLS loggers.
 */
void cephsan_cleanup(void)
{
	int cpu;
	struct ceph_san_tls_logger *tls;

	for_each_possible_cpu(cpu) {
		tls = per_cpu_ptr(&ceph_san_tls, cpu);
		if (tls->pages) {
			free_pages((unsigned long)tls->pages, get_order(CEPH_SAN_MAX_LOGS * sizeof(struct ceph_san_log_entry)));
			tls->pages = NULL;
		}
	}
}
EXPORT_SYMBOL(cephsan_cleanup);
/* Initialize the Ceph SAN logging infrastructure.
 * Call this at module init to set up the global list and lock.
 */
int cephsan_init(void)
{
	int cpu;
	struct ceph_san_tls_logger *tls;

	for_each_possible_cpu(cpu) {
		tls = per_cpu_ptr(&ceph_san_tls, cpu);
		tls->pages = alloc_pages(GFP_KERNEL, get_order(CEPH_SAN_MAX_LOGS * sizeof(struct ceph_san_log_entry)));
		if (!tls->pages) {
			pr_err("Failed to allocate TLS logs for CPU %d\n", cpu);
			return -ENOMEM;
		}
		tls->logs = (struct ceph_san_log_entry *)page_address(tls->pages);
	}
	return 0;
}
EXPORT_SYMBOL(cephsan_init);

/**
 * cephsan_pagefrag_init - Initialize the pagefrag allocator.
 *
 * Allocates a 16KB contiguous buffer and resets head and tail pointers.
 *
 * Return: 0 on success, negative error code on failure.
 */
int cephsan_pagefrag_init(struct cephsan_pagefrag *pf)
{
	pf->buffer = kmalloc(CEPHSAN_PAGEFRAG_SIZE, GFP_KERNEL);
	if (!pf->buffer)
		return -ENOMEM;

	pf->head = 0;
	pf->tail = 0;
	return 0;
}
EXPORT_SYMBOL(cephsan_pagefrag_init);

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
EXPORT_SYMBOL(cephsan_pagefrag_alloc);
/**
 * cephsan_pagefrag_free - Free bytes in the pagefrag allocator.
 * @n: number of bytes to free.
 *
 * Advances the tail pointer by @n bytes (wrapping around if needed).
 */
void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n)
{
	pf->tail = (pf->tail + n) % CEPHSAN_PAGEFRAG_SIZE;
}
EXPORT_SYMBOL(cephsan_pagefrag_free);
/**
 * cephsan_pagefrag_deinit - Deinitialize the pagefrag allocator.
 *
 * Frees the allocated buffer and resets the head and tail pointers.
 */
void cephsan_pagefrag_deinit(struct cephsan_pagefrag *pf)
{
	kfree(pf->buffer);
	pf->buffer = NULL;
	pf->head = pf->tail = 0;
}
EXPORT_SYMBOL(cephsan_pagefrag_deinit);