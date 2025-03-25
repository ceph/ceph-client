#ifndef CEPH_SAN_LOGGER_H
#define CEPH_SAN_LOGGER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ceph/ceph_san_batch.h>
#include <linux/ceph/ceph_san_pagefrag.h>
#include <linux/stdarg.h>

/* Maximum length of a log entry buffer */
#define CEPH_SAN_LOG_MAX_LEN 256
#define CEPH_SAN_LOG_ENTRY_POISON 0xDEADBEEF
#define CEPH_SAN_LOG_MAX_REGISTRATIONS 1024

/* Helper function to format jiffies into human readable time */
int jiffies_to_formatted_time(unsigned long jiffies_value, char *buffer, size_t buffer_len);

/* Get TLS context for current task */
struct ceph_san_tls_ctx *ceph_san_get_tls_ctx(void);

/* Log a message with file, function, and line information */
void ceph_san_log(const char *file, const char *func, unsigned int line, const char *fmt, ...);

/* Log registration structure */
struct ceph_san_log_registration {
    const char *file;          /* Source file - static pointer */
    const char *func;          /* Source function - static pointer */
    unsigned int line;         /* Line number */
    const char *fmt;           /* Format string - static pointer */
    unsigned int id;           /* Unique registration ID */
    size_t params_size;        /* Size of all parameters when compacted */
};

/* Log entry structure */
struct ceph_san_log_entry {
    u64 debug_poison;           /* Debug poison value */
    u64 ts;                     /* Timestamp (jiffies) */
    unsigned int reg_id;        /* Registration ID */
    unsigned int len;           /* Length of the message */
    char *buffer;              /* Flexible array for inline buffer */
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

/* Register a log location and get unique ID */
unsigned int ceph_san_log_register(const char *file, const char *func,
                                 unsigned int line, const char *fmt);

/* Log a message using registration ID */
void ceph_san_log_with_id(unsigned int reg_id, const char *fmt, ...);

/* Helper macro for logging */
#define CEPH_SAN_LOG(fmt, ...) \
    do { \
        static unsigned int __log_id = 0; \
        if (unlikely(!__log_id)) \
            __log_id = ceph_san_log_register(kbasename(__FILE__), __func__, \
                                           __LINE__, fmt); \
        ceph_san_log_with_id(__log_id, fmt, ##__VA_ARGS__); \
    } while (0)

/* Global logger instance */
extern struct ceph_san_logger g_logger;
extern struct ceph_san_log_registration g_registrations[];

extern void ceph_san_log_with_id_v(unsigned int reg_id, const char *fmt, va_list args);

#endif /* CEPH_SAN_LOGGER_H */