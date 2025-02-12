#ifndef CEPHSAN_H
#define CEPHSAN_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

extern struct list_head ceph_san_list;
extern spinlock_t ceph_san_lock;

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
#define CEPH_SAN_MAX_LOGS 256
#define LOG_BUF_SIZE 128

void cephsan_cleanup(void);
int cephsan_init(void);

char *get_log_cephsan(void);
#define CEPH_SAN_LOG(fmt, ...) do { \
    char *buf = get_log_cephsan(); \
    if (buf) { \
        snprintf(buf, LOG_BUF_SIZE, fmt, ##__VA_ARGS__); \
    }   \
} while (0)
/*
 * Internal definitions for Ceph SAN logs.
 * These definitions are not part of the public API but are required by debugfs.c.
 */
struct ceph_san_log_entry {
    char buf[LOG_BUF_SIZE];
    u64 ts;
};

struct ceph_san_tls_logger {
    u64 cephsun_sig;
    size_t head_idx;
    size_t tail_idx;
    struct list_head list;
    struct task_struct *task;
    struct ceph_mds_request *req;
    struct ceph_san_log_entry logs[CEPH_SAN_MAX_LOGS];
};
/* Macro to set the request in the TLS logger */
#define CEPH_SAN_SET_REQ(req) do { \
    struct ceph_san_tls_logger *__tls = current->journal_info; \
    if (__tls && __tls->cephsun_sig == 0xD1E7C0CE) \
        __tls->req = req; \
    else \
        current->journal_info = req; \
} while (0)
/* Macro to reset the request in the TLS logger */
#define CEPH_SAN_RESET_REQ() do { \
    struct ceph_san_tls_logger *__tls = current->journal_info; \
    if (__tls && __tls->cephsun_sig == 0xD1E7C0CE) \
        __tls->req = NULL; \
    else \
        current->journal_info = NULL; \
} while (0)

/* Macro to get the request from the TLS logger */
#define CEPH_SAN_GET_REQ() ({ \
    struct ceph_san_tls_logger *__tls = current->journal_info; \
    (__tls && __tls->cephsun_sig == 0xD1E7C0CE) ? __tls->req : current->journal_info; \
})
#else /* CONFIG_DEBUG_FS */
#define CEPH_SAN_LOG(param) do {} while (0)
#define CEPH_SAN_SET_REQ(req) do { current->journal_info = req; } while (0)
#define CEPH_SAN_RESET_REQ() do { current->journal_info = NULL; } while (0)
#define CEPH_SAN_GET_REQ() (current->journal_info)


static inline void cephsan_cleanup(void) {}
static inline int __init cephsan_init(void) { return 0; }

#endif /* CONFIG_DEBUG_FS */

#endif /* CEPHSAN_H */