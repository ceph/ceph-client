#ifndef CEPH_SAN_LOGGER_H
#define CEPH_SAN_LOGGER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ceph/ceph_san_batch.h>
#include <linux/ceph/ceph_san_pagefrag.h>
#include <linux/ceph/ceph_san_ser.h>

/* Maximum length of a log entry buffer */
#define CEPH_SAN_LOG_MAX_LEN 256
#define CEPH_SAN_LOG_ENTRY_POISON 0xDEADBEEF
#define CEPH_SAN_MAX_SOURCE_IDS 4096

/* Source information mapping structure */
struct ceph_san_source_info {
    const char *file;
    const char *func;
    unsigned int line;
    const char *fmt;         /* Format string */
};

/* Log entry structure */
struct ceph_san_log_entry {
    u64 debug_poison;           /* Debug poison value */
    u64 ts;                     /* Timestamp (jiffies) */
    u32 source_id;              /* ID for source file/function/line */
    unsigned int len;           /* Length of the message */
    char *buffer;               /* Flexible array for inline buffer */
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
    struct ceph_san_source_info source_map[CEPH_SAN_MAX_SOURCE_IDS]; /* Source info mapping */
    atomic_t next_source_id;    /* Next source ID to assign */
};

/* Iterator for log entries in a single pagefrag */
struct ceph_san_log_iter {
    struct cephsan_pagefrag *pf;    /* Pagefrag being iterated */
    u64 current_offset;             /* Current offset in pagefrag */
    u64 end_offset;                 /* End offset in pagefrag */
    u64 prev_offset;               /* Previous offset for debugging */
    u64 steps;                     /* Number of steps taken */
};

/* Initialize the iterator for a specific pagefrag */
void ceph_san_log_iter_init(struct ceph_san_log_iter *iter, struct cephsan_pagefrag *pf);

/* Get next log entry, returns NULL when no more entries */
struct ceph_san_log_entry *ceph_san_log_iter_next(struct ceph_san_log_iter *iter);

/* Initialize the logging system */
int ceph_san_logger_init(void);

/* Clean up the logging system */
void ceph_san_logger_cleanup(void);

/* Get or create source ID */
u32 ceph_san_get_source_id(const char *file, const char *func, unsigned int line, const char *fmt);

/* Get source information for ID */
const struct ceph_san_source_info *ceph_san_get_source_info(u32 id);

/* Log a message */
void ceph_san_log(u32 source_id, ...);

/* Get current TLS context, creating if necessary */
struct ceph_san_tls_ctx *ceph_san_get_tls_ctx(void);

/* Helper macro for logging */
#define CEPH_SAN_LOG(fmt, ...) \
    do { \
        static u32 __source_id = 0; \
        static size_t __size = 0; \
        if (unlikely(__source_id == 0)) { \
            __source_id = ceph_san_get_source_id(kbasename(__FILE__), __func__, __LINE__, fmt); \
            __size = ceph_san_cnt(__VA_ARGS__); \
        } \
        ceph_san_log(__source_id, ##__VA_ARGS__); \
    } while (0)

/* Global logger instance */
extern struct ceph_san_logger g_logger;

#endif /* CEPH_SAN_LOGGER_H */
