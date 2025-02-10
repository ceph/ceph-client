#ifndef CEPHSAN_H
#define CEPHSAN_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>


DECLARE_PER_CPU(struct ceph_san_tls_logger, ceph_san_tls);
DECLARE_PER_CPU(struct cephsan_pagefrag, ceph_san_pagefrag);

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

#define CEPHSAN_PAGEFRAG_SIZE  (1<<22)  /* 4MB */

/* Pagefrag allocator structure */
struct cephsan_pagefrag {
    struct page *pages;
    void *buffer;
    unsigned int head;
    unsigned int tail;
};

/* The ceph san log entry structure is now private to ceph_san.c.
 * Use log_cephsan() below.
 */

/* get_cephsan() and alloc_cephsan() have been removed from the public API. */

/* New log_cephsan now accepts a line number, a pointer to a u8 buffer (typically function name),
 * and an optional parameter. It uses the current task's journal_info field.
 */

int cephsan_pagefrag_init(struct cephsan_pagefrag *pf);


/**
 * cephsan_pagefrag_alloc - Allocate bytes from the pagefrag buffer.
 * @n: number of bytes to allocate.
 *
 * Allocates @n bytes if there is sufficient free space in the buffer.
 * Advances the head pointer by @n bytes (wrapping around if needed).
 *
 * Return: pointer to the allocated memory, or NULL if not enough space.
 */
u64 cephsan_pagefrag_alloc(struct cephsan_pagefrag *pf, unsigned int n);

/**
 * cephsan_pagefrag_free - Free bytes in the pagefrag allocator.
 * @n: number of bytes to free.
 *
 * Advances the tail pointer by @n bytes (wrapping around if needed).
 */
void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n);
/**
 * cephsan_pagefrag_deinit - Deinitialize the pagefrag allocator.
 *
 * Frees the allocated buffer and resets the head and tail pointers.
 */
void cephsan_pagefrag_deinit(struct cephsan_pagefrag *pf);


#ifdef CONFIG_DEBUG_FS
#define CEPH_SAN_MAX_LOGS (8192 << 2) //4MB per core
#define LOG_BUF_SIZE 256

void cephsan_cleanup(void);
int cephsan_init(void);

void log_cephsan(char *buf);
#define CEPH_SAN_LOG(fmt, ...) do { \
    char buf[LOG_BUF_SIZE] = {0}; \
    snprintf(buf, LOG_BUF_SIZE, fmt, ##__VA_ARGS__); \
    log_cephsan(buf); \
} while (0)
/*
 * Internal definitions for Ceph SAN logs.
 * These definitions are not part of the public API but are required by debugfs.c.
 */
struct ceph_san_log_entry {
    char comm[TASK_COMM_LEN];
    char *buf;
    u64 ts;
    pid_t pid;
    u32 len;
};

struct ceph_san_tls_logger {
    size_t head_idx;
    struct page *pages;
    struct ceph_san_log_entry *logs;
};
#else /* CONFIG_DEBUG_FS */

#define CEPH_SAN_LOG(param) do {} while (0)

static inline void cephsan_cleanup(void) {}
static inline int __init cephsan_init(void) { return 0; }

#endif /* CONFIG_DEBUG_FS */

#define CEPH_SAN_SET_REQ(req) do { current->journal_info = req; } while (0)
#define CEPH_SAN_RESET_REQ() do { current->journal_info = NULL; } while (0)
#define CEPH_SAN_GET_REQ() (current->journal_info)

#endif /* CEPHSAN_H */
