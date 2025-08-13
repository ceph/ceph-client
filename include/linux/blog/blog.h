/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Binary Logging Infrastructure (BLOG)
 *
 * Generic binary logging infrastructure for kernel subsystems.
 * Modules maintain their own client mappings and debugfs interfaces.
 */
#ifndef _LINUX_BLOG_H
#define _LINUX_BLOG_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/blog/blog_batch.h>
#include <linux/blog/blog_pagefrag.h>
#include <linux/blog/blog_ser.h>
#include <linux/blog/blog_des.h>

/* Debug configuration */
#ifdef CONFIG_BLOG_DEBUG
#define BLOG_DEBUG_POISON 1
#else
#define BLOG_DEBUG_POISON 0
#endif

#ifdef CONFIG_BLOG_TRACK_USAGE
#define BLOG_TRACK_USAGE 1
#else
#define BLOG_TRACK_USAGE 0
#endif

/* Debug poison values */
#if BLOG_DEBUG_POISON
#define BLOG_LOG_ENTRY_POISON 0xD1E7C0DE
#define BLOG_CTX_POISON       0xCAFEBABE
#endif

/* Global logger instance */
extern struct blog_logger g_blog_logger;

/* Maximum values */
#define BLOG_LOG_MAX_LEN 256
#ifdef CONFIG_BLOG_MAX_SOURCES
#define BLOG_MAX_SOURCE_IDS CONFIG_BLOG_MAX_SOURCES
#else
#define BLOG_MAX_SOURCE_IDS 4096
#endif
#ifdef CONFIG_BLOG_MAX_CLIENTS
#define BLOG_MAX_CLIENT_IDS CONFIG_BLOG_MAX_CLIENTS
#else
#define BLOG_MAX_CLIENT_IDS 256
#endif

/* Source information mapping structure - preserves all ceph_san fields */
struct blog_source_info {
	const char *file;
	const char *func;
	unsigned int line;
	const char *fmt;         /* Format string */
	int warn_count;
#if BLOG_TRACK_USAGE
	atomic_t napi_usage;     /* Number of times used in NAPI context */
	atomic_t task_usage;     /* Number of times used in task context */
	atomic_t napi_bytes;     /* Total bytes used in NAPI context */
	atomic_t task_bytes;     /* Total bytes used in task context */
#endif
};

/* Log entry structure - preserves all ceph_san fields */
struct blog_log_entry {
#if BLOG_DEBUG_POISON
	u64 debug_poison;        /* Debug poison value */
#endif
	u32 ts_delta;            /* Time delta from base_jiffies */
	u16 source_id;           /* Source ID */
	u8 client_id;            /* Client ID (module-specific) */
	u8 len;                  /* Length of buffer */
	char buffer[];           /* Variable length buffer */
};

/* TLS context structure - preserves all ceph_san fields */
struct blog_tls_ctx {
	struct list_head list;      /* List entry for global list */
	struct blog_pagefrag pf;    /* Page fragment for this context */
	void (*release)(void *);    /* Release function */
	atomic_t refcount;          /* Reference count */
	struct task_struct *task;   /* Associated task */
	pid_t pid;                  /* Process ID */
	char comm[TASK_COMM_LEN];   /* Command name */
	u64 id;                     /* Unique context ID */
	u64 debug_poison;           /* Debug poison value */
	unsigned long base_jiffies; /* Base jiffies value for this context */
};

/* Global logger state - preserves all ceph_san fields */
struct blog_logger {
	struct list_head contexts;   /* List of all TLS contexts */
	spinlock_t lock;            /* Protects contexts list */
	struct blog_batch alloc_batch;  /* Batch for allocating new entries */
	struct blog_batch log_batch;    /* Batch for storing log entries */
	struct blog_source_info source_map[BLOG_MAX_SOURCE_IDS]; /* Source info mapping */
	atomic_t next_source_id;    /* Next source ID to assign */
	spinlock_t source_lock;     /* Protects source operations */
	unsigned long total_contexts_allocated;
	u64 next_ctx_id;           /* Next context ID to assign */
	spinlock_t ctx_id_lock;    /* Protects context ID counter */
	struct blog_tls_ctx __percpu *napi_ctxs; /* Per-CPU NAPI contexts */
};

/* Iterator for log entries in a single pagefrag */
struct blog_log_iter {
	struct blog_pagefrag *pf;    /* Pagefrag being iterated */
	u64 current_offset;          /* Current offset in pagefrag */
	u64 end_offset;              /* End offset in pagefrag */
	u64 prev_offset;             /* Previous offset for debugging */
	u64 steps;                   /* Number of steps taken */
};

/* Client deserialization callback type */
typedef int (*blog_client_des_fn)(char *buf, size_t size, u8 client_id);

/* Core API functions */

/* Initialize the logging system */
int blog_init(void);

/* Clean up the logging system */
void blog_cleanup(void);

/* Get or create source ID */
u32 blog_get_source_id(const char *file, const char *func, unsigned int line, const char *fmt);

/* Get source information for ID */
struct blog_source_info *blog_get_source_info(u32 id);

/* Log a message - returns buffer to write to */
void* blog_log(u32 source_id, u8 client_id, size_t needed_size);

/* Get current TLS context, creating if necessary */
struct blog_tls_ctx *blog_get_tls_ctx(void);

/* Get NAPI context for current CPU */
struct blog_tls_ctx *blog_get_napi_ctx(void);

/* Set NAPI context for current CPU */
void blog_set_napi_ctx(struct blog_tls_ctx *ctx);

/* Get appropriate context based on context type */
struct blog_tls_ctx *blog_get_ctx(void);

/* Trim the current context's pagefrag by n bytes */
int blog_log_trim(unsigned int n);

/* Initialize the iterator for a specific pagefrag */
void blog_log_iter_init(struct blog_log_iter *iter, struct blog_pagefrag *pf);

/* Get next log entry, returns NULL when no more entries */
struct blog_log_entry *blog_log_iter_next(struct blog_log_iter *iter);

/* Deserialization with callback */
int blog_des_entry(struct blog_log_entry *entry, char *output, size_t out_size,
                   blog_client_des_fn client_cb);

/* Helper functions */
static inline void blog_logger_print_stats(struct blog_logger *logger)
{
	pr_debug("blog: total_contexts=%lu, alloc_batch={empty=%d, full=%d}, log_batch={empty=%d, full=%d}\n",
	         logger->total_contexts_allocated,
	         logger->alloc_batch.nr_empty, logger->alloc_batch.nr_full,
	         logger->log_batch.nr_empty, logger->log_batch.nr_full);
}

/* Check if address is in valid kernel address range */
bool blog_is_valid_kernel_addr(const void *addr);

/* Helper macro for logging */
#define __BLOG_LOG(dbg, __client_id, fmt, ...) \
	do { \
		static u32 __source_id = 0; \
		static size_t __size = 0; \
		void *___buffer = NULL; \
		if (unlikely(__source_id == 0)) { \
			__source_id = blog_get_source_id(kbasename(__FILE__), __func__, __LINE__, fmt); \
			__size = blog_cnt(__VA_ARGS__); \
		} \
		___buffer = blog_log(__source_id, __client_id, __size); \
		if (likely(___buffer) && __size > 0) {	\
			void *___tmp = ___buffer; \
			size_t actual_size; \
			blog_ser(___buffer, ##__VA_ARGS__);\
			actual_size = ___buffer - ___tmp; \
			blog_log_trim(__size - actual_size); \
		} \
	} while (0)

#define BLOG_LOG(fmt, ...) \
	__BLOG_LOG(0, 0, fmt, ##__VA_ARGS__)

/* Helper macro for logging with client ID */
#define BLOG_LOG_CLIENT(client_id, fmt, ...) \
	__BLOG_LOG(0, client_id, fmt, ##__VA_ARGS__)

#endif /* _LINUX_BLOG_H */
