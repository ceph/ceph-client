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

DEFINE_PER_CPU(struct cephsan_pagefrag, ceph_san_pagefrag);
EXPORT_SYMBOL(ceph_san_pagefrag);


static inline void *cephsan_pagefrag_get_ptr(struct cephsan_pagefrag *pf, u64 val);
/* The definitions for struct ceph_san_log_entry and struct ceph_san_tls_logger
 * have been moved to cephsan.h (under CONFIG_DEBUG_FS) to avoid duplication.
 */

void log_cephsan(char *buf) {
    /* Use the per-core TLS logger */
    u64 buf_idx;
    int len = strlen(buf);
    struct ceph_san_tls_logger *tls = this_cpu_ptr(&ceph_san_tls);
    struct cephsan_pagefrag *pf = this_cpu_ptr(&ceph_san_pagefrag);

    int head_idx = tls->head_idx + 1 & (CEPH_SAN_MAX_LOGS - 1);
    int pre_len = tls->logs[head_idx].len;

    buf[len-1] = '\0';
    tls->logs[head_idx].pid = current->pid;
    tls->logs[head_idx].ts = jiffies;
    memcpy(tls->logs[head_idx].comm, current->comm, TASK_COMM_LEN);

    cephsan_pagefrag_free(pf, pre_len);
    tls->logs[head_idx].len = 0;

    buf_idx = cephsan_pagefrag_alloc(pf, len);
    if (buf_idx) {
		tls->head_idx = head_idx;
		tls->histogram.counters[len >> 3]++;
		tls->logs[head_idx].len = len;
        tls->logs[head_idx].buf = cephsan_pagefrag_get_ptr(pf, buf_idx);
		memcpy(tls->logs[head_idx].buf, buf, len);
    }
}
EXPORT_SYMBOL(log_cephsan);

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
	struct cephsan_pagefrag *pf;

	for_each_possible_cpu(cpu) {
		tls = per_cpu_ptr(&ceph_san_tls, cpu);
		tls->pages = alloc_pages(GFP_KERNEL, get_order(CEPH_SAN_MAX_LOGS * sizeof(struct ceph_san_log_entry)));
		if (!tls->pages) {
			pr_err("Failed to allocate TLS logs for CPU %d\n", cpu);
			return -ENOMEM;
		}
		tls->logs = (struct ceph_san_log_entry *)page_address(tls->pages);
	}

	for_each_possible_cpu(cpu) {
		pf = per_cpu_ptr(&ceph_san_pagefrag, cpu);
		cephsan_pagefrag_init(pf);
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
static inline void *cephsan_pagefrag_get_ptr(struct cephsan_pagefrag *pf, u64 val)
{
	return pf->buffer + (val & 0xFFFFFFFF);
}

#define CEPHSAN_PAGEFRAG_GET_N(val)  ((val) >> 32)

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
	kfree(pf->buffer);
	pf->buffer = NULL;
	pf->head = pf->tail = 0;
}
EXPORT_SYMBOL(cephsan_pagefrag_deinit);
