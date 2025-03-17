#ifndef CEPH_SAN_LOGGER_H
#define CEPH_SAN_LOGGER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ceph/ceph_san_batch.h>
#include <linux/ceph/ceph_san_pagefrag.h>

/* Maximum length of a log entry buffer */
#define CEPH_SAN_LOG_MAX_LEN 256
#define CEPH_SAN_LOG_ENTRY_POISON 0xDEADBEEF
/* Log entry structure */
struct ceph_san_log_entry {
    u64 debug_poison;           /* Debug poison value */
    u64 ts;                     /* Timestamp (jiffies) */
    unsigned int line;          /* Line number */
    unsigned int len;           /* Length of the message */
    const char *file;          /* Source file */
    char buffer[0];            /* Flexible array for inline buffer */
};

/* TLS context structure */
struct ceph_san_tls_ctx {
    char comm[TASK_COMM_LEN];   /* Task command name */
    pid_t pid;                  /* Process ID */
    struct task_struct *task;    /* Pointer to task struct */
    struct cephsan_pagefrag pf; /* Pagefrag for this context */
    struct list_head list;      /* For global list of contexts */
};

/* Global logger state */
struct ceph_san_logger {
    struct list_head contexts;   /* List of all TLS contexts */
    spinlock_t lock;            /* Protects contexts list */
    struct ceph_san_batch alloc_batch;  /* Batch for allocating new entries */
    struct ceph_san_batch log_batch;    /* Batch for storing log entries */
};

/* Iterator for log entries in a single pagefrag */
struct ceph_san_log_iter {
    struct cephsan_pagefrag *pf;    /* Pagefrag being iterated */
    u64 current_offset;             /* Current offset in pagefrag */
    u64 end_offset;                 /* End offset in pagefrag */
};

/* Initialize the iterator for a specific pagefrag */
void ceph_san_log_iter_init(struct ceph_san_log_iter *iter, struct cephsan_pagefrag *pf);

/* Get next log entry, returns NULL when no more entries */
struct ceph_san_log_entry *ceph_san_log_iter_next(struct ceph_san_log_iter *iter);

/* Initialize the logging system */
int ceph_san_logger_init(void);

/* Clean up the logging system */
void ceph_san_logger_cleanup(void);

/* Log a message */
void ceph_san_log(const char *file, unsigned int line, const char *fmt, ...);

/* Get current TLS context, creating if necessary */
struct ceph_san_tls_ctx *ceph_san_get_tls_ctx(void);

/* Helper macro for logging */
#define CEPH_SAN_LOG(fmt, ...) \
    ceph_san_log(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif /* CEPH_SAN_LOGGER_H */