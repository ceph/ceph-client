#ifndef CEPH_SAN_LOGGER_H
#define CEPH_SAN_LOGGER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ceph/ceph_san_batch.h>
#include <linux/ceph/ceph_san_pagefrag.h>
#include <linux/ceph/ceph_san_ser.h>
#include <linux/ceph/ceph_san_des.h>

/* Debug poison values */
#define CEPH_SAN_DEBUG_POISON 0
#if CEPH_SAN_DEBUG_POISON
#define CEPH_SAN_LOG_ENTRY_POISON 0xD1E7C0DE
#endif

/* Enable usage statistics tracking */
#define CEPH_SAN_TRACK_USAGE 0

/* Global logger instance */
extern struct ceph_san_logger g_logger;

/* Maximum length of a log entry buffer */
#define CEPH_SAN_CTX_POISON       0xCAFEBABE
#define CEPH_SAN_LOG_MAX_LEN 256
#define CEPH_SAN_MAX_SOURCE_IDS 4096
#define CEPH_SAN_MAX_CLIENT_IDS 256

/* Client ID cache entry */
struct ceph_san_client_id {
    char fsid[16];         /* Client FSID */
    u64 global_id;         /* Client global ID */
};

/* Source information mapping structure */
struct ceph_san_source_info {
    const char *file;
    const char *func;
    unsigned int line;
    const char *fmt;         /* Format string */
    int warn_count;
#if CEPH_SAN_TRACK_USAGE
    atomic_t napi_usage;     /* Number of times used in NAPI context */
    atomic_t task_usage;     /* Number of times used in task context */
    atomic_t napi_bytes;     /* Total bytes used in NAPI context */
    atomic_t task_bytes;     /* Total bytes used in task context */
#endif
};

/* Log entry structure - optimized for size */
struct ceph_san_log_entry {
#if CEPH_SAN_DEBUG_POISON
    u64 debug_poison;           /* Debug poison value */
#endif
    u32 ts_delta;              /* Time delta from base_jiffies */
    u16 source_id;             /* Source ID */
    u8 client_id;             /* Client ID */
    u8 len;                   /* Length of buffer */
    char buffer[];             /* Variable length buffer */
};

/* TLS context structure */
struct ceph_san_tls_ctx {
    struct list_head list;      /* List entry for global list */
    struct cephsan_pagefrag pf; /* Page fragment for this context */
    void (*release)(void *);    /* Release function */
    atomic_t refcount;          /* Reference count */
    struct task_struct *task;   /* Associated task */
    pid_t pid;                  /* Process ID */
    char comm[TASK_COMM_LEN];   /* Command name */
    u64 id;                     /* Unique context ID */
    u64 debug_poison;           /* Debug poison value */
    unsigned long base_jiffies; /* Base jiffies value for this context */
};

/* Global logger state */
struct ceph_san_logger {
    struct list_head contexts;   /* List of all TLS contexts */
    spinlock_t lock;            /* Protects contexts list */
    struct ceph_san_batch alloc_batch;  /* Batch for allocating new entries */
    struct ceph_san_batch log_batch;    /* Batch for storing log entries */
    struct ceph_san_source_info source_map[CEPH_SAN_MAX_SOURCE_IDS]; /* Source info mapping */
    struct ceph_san_client_id client_map[CEPH_SAN_MAX_CLIENT_IDS]; /* Client ID mapping */
    atomic_t next_source_id;    /* Next source ID to assign */
    u32 next_client_id;        /* Next client ID to assign */
    spinlock_t client_lock;     /* Protects client ID operations */
    unsigned long total_contexts_allocated;
    u64 next_ctx_id;           /* Next context ID to assign */
    spinlock_t ctx_id_lock;    /* Protects context ID counter */
    struct ceph_san_tls_ctx __percpu *napi_ctxs; /* Per-CPU NAPI contexts */
};

static inline void ceph_san_logger_print_stats(struct ceph_san_logger *logger)
{
    pr_debug("ceph_san_logger: total_contexts=%lu, alloc_batch={empty=%d, full=%d}, log_batch={empty=%d, full=%d}\n",
            logger->total_contexts_allocated,
            logger->alloc_batch.nr_empty, logger->alloc_batch.nr_full,
            logger->log_batch.nr_empty, logger->log_batch.nr_full);
}

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

/* Reconstruct a formatted string from a log entry */
int ceph_san_log_reconstruct(const struct ceph_san_log_entry *entry, char *output, size_t output_size);

/* Initialize the logging system */
int ceph_san_logger_init(void);

/* Clean up the logging system */
void ceph_san_logger_cleanup(void);

/* Get or create source ID */
u32 ceph_san_get_source_id(const char *file, const char *func, unsigned int line, const char *fmt);

/* Get source information for ID */
struct ceph_san_source_info *ceph_san_get_source_info(u32 id);

/* Check if client ID matches given fsid and global_id, returning the actual ID */
u32 ceph_san_check_client_id(u32 id, const char *fsid, u64 global_id);

/* Get client information for ID */
const struct ceph_san_client_id *ceph_san_get_client_info(u32 id);

/* Log a message */
void* ceph_san_log(u32 source_id, u32 client_id, size_t needed_size);

/* Get current TLS context, creating if necessary */
struct ceph_san_tls_ctx *ceph_san_get_tls_ctx(void);

/* Get NAPI context for current CPU */
struct ceph_san_tls_ctx *ceph_san_get_napi_ctx(void);

/* Set NAPI context for current CPU */
void ceph_san_set_napi_ctx(struct ceph_san_tls_ctx *ctx);

/* Get appropriate context based on context type */
struct ceph_san_tls_ctx *ceph_san_get_ctx(void);

/* Trim the current context's pagefrag by n bytes */
int ceph_san_log_trim(unsigned int n);

/**
 * is_valid_kernel_addr - Check if address is in valid kernel address range
 * @addr: Address to check
 *
 * Returns true if address is in valid kernel address range
 */
bool is_valid_kernel_addr(const void *addr);

/* Helper macro for logging */
#define __CEPH_SAN_LOG(dbg, __client_id, fmt, ...) \
    do { \
        static u32 __source_id = 0; \
        static size_t __size = 0; \
        void *___buffer = NULL; \
        if (unlikely(__source_id == 0)) { \
            __source_id = ceph_san_get_source_id(kbasename(__FILE__), __func__, __LINE__, fmt); \
            __size = ceph_san_cnt(__VA_ARGS__); \
        } \
        ___buffer = ceph_san_log(__source_id, __client_id, __size); \
        if (likely(___buffer) && __size > 0) {	\
            void *___tmp = ___buffer; \
            size_t actual_size; \
        	ceph_san_ser(___buffer, ##__VA_ARGS__);\
            actual_size = ___buffer - ___tmp; \
            ceph_san_log_trim(__size - actual_size); \
        } \
    } while (0)

#define CEPH_SAN_LOG(fmt, ...) \
    __CEPH_SAN_LOG(0, 0, fmt, ##__VA_ARGS__)

/* Helper macro for logging with client ID */
#define CEPH_SAN_LOG_CLIENT(client, fmt, ...) \
    do { \
        static u32 __client_id; \
        __client_id = ceph_san_check_client_id(__client_id, client->fsid.fsid, client->monc.auth->global_id); \
        __CEPH_SAN_LOG(0, __client_id, fmt, ##__VA_ARGS__); \
    } while (0)

#endif /* CEPH_SAN_LOGGER_H */
