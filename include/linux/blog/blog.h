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
#define BLOG_CTX_POISON 0xCAFEBABE
#endif

/* No global logger - all logging must use per-module contexts */

/* Maximum values */
#define BLOG_MAX_PAYLOAD 255
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

/**
 * struct blog_source_info - Source location metadata for log entries
 * @file: Source file name (from __FILE__)
 * @func: Function name (from __func__)
 * @line: Line number (from __LINE__)
 * @fmt: Printf-style format string for this log site
 * @warn_count: Number of warnings issued from this site
 * @napi_usage: Number of times logged from NAPI context (if BLOG_TRACK_USAGE)
 * @task_usage: Number of times logged from task context (if BLOG_TRACK_USAGE)
 * @napi_bytes: Total bytes logged from NAPI (if BLOG_TRACK_USAGE)
 * @task_bytes: Total bytes logged from task (if BLOG_TRACK_USAGE)
 *
 * Maps source IDs to their original source locations. One entry per unique
 * file:func:line location. The format string is stored here for use during
 * deserialization to reconstruct the original log message.
 */
struct blog_source_info {
	const char *file;
	const char *func;
	unsigned int line;
	const char *fmt;
	int warn_count;
#if BLOG_TRACK_USAGE
	atomic_t napi_usage;
	atomic_t task_usage;
	atomic_t napi_bytes;
	atomic_t task_bytes;
#endif
};

/**
 * struct blog_log_entry - Binary log entry header and payload
 * @debug_poison: Magic value for corruption detection (if BLOG_DEBUG_POISON)
 * @ts_delta: Timestamp delta from context's base_jiffies
 * @source_id: Source location ID (index into source_map)
 * @len: Length of serialized data in buffer (max 255)
 * @client_id: Module-specific client identifier
 * @flags: Reserved for future use
 * @buffer: Variable-length serialized argument data
 *
 * Wire format for a single log entry. Entries are stored sequentially in
 * the pagefrag buffer. The buffer contains binary-serialized arguments
 * that match the format string stored in source_map[source_id].
 */
struct blog_log_entry {
#if BLOG_DEBUG_POISON
	u64 debug_poison;
#endif
	u32 ts_delta;
	u16 source_id;
	u8 len;
	u8 client_id;
	u8 flags;
	char buffer[];
};

/**
 * struct blog_tls_ctx - Per-task (or NAPI) logging context
 * @list: Linkage in logger's contexts list
 * @pf: Page fragment allocator (512KB buffer)
 * @release: Cleanup function called on context destruction
 * @refcount: Reference count (0=in batch, 1=active)
 * @task: Associated task (NULL for NAPI contexts)
 * @pid: Process ID of associated task
 * @comm: Command name of associated task
 * @id: Unique context ID (for debugging)
 * @debug_poison: Magic value for corruption detection (if BLOG_DEBUG_POISON)
 * @base_jiffies: Base timestamp for delta calculation
 * @logger: Parent logger instance
 *
 * Each task (or CPU for NAPI) has its own logging context with a 512KB
 * buffer. Contexts are created on first log and persist until task exit
 * or module cleanup. They're recycled through magazine batching system.
 */
struct blog_tls_ctx {
	struct list_head list;
	struct blog_pagefrag pf;
	void (*release)(void *);
	atomic_t refcount;
	struct task_struct *task;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	u64 id;
	u64 debug_poison;
	unsigned long base_jiffies;
	struct blog_logger *logger;
};

/**
 * struct blog_logger - Per-module logger instance
 * @contexts: List of all TLS contexts for this logger
 * @lock: Protects contexts list
 * @alloc_batch: Magazine batch for context allocation
 * @log_batch: Magazine batch for completed log contexts
 * @source_map: Array mapping source IDs to source info (max 4096)
 * @next_source_id: Next source ID to assign
 * @source_lock: Protects source map operations
 * @total_contexts_allocated: Total number of contexts created
 * @next_ctx_id: Next context ID to assign
 * @ctx_id_lock: Protects context ID counter
 * @napi_ctxs: Per-CPU NAPI context pointers
 *
 * Each module has its own logger instance with isolated source ID space,
 * context list, and batching system. This provides full isolation between
 * modules.
 */
struct blog_logger {
	struct list_head contexts;
	spinlock_t lock;
	struct blog_batch alloc_batch;
	struct blog_batch log_batch;
	struct blog_source_info
		source_map[BLOG_MAX_SOURCE_IDS];
	atomic_t next_source_id;
	spinlock_t source_lock;
	unsigned long total_contexts_allocated;
	u64 next_ctx_id;
	spinlock_t ctx_id_lock;
	struct blog_tls_ctx *__percpu
		*napi_ctxs;
};

/**
 * struct blog_log_iter - Iterator for reading log entries from a pagefrag
 * @pf: Pagefrag being iterated
 * @current_offset: Current read position in pagefrag
 * @end_offset: End position (pf->head at iteration start)
 * @prev_offset: Previous offset (for debugging)
 * @steps: Number of entries iterated so far
 *
 * Used to walk through all log entries in a pagefrag sequentially.
 * Initialize with blog_log_iter_init(), then call blog_log_iter_next()
 * repeatedly until it returns NULL.
 */
struct blog_log_iter {
	struct blog_pagefrag *pf;
	u64 current_offset;
	u64 end_offset;
	u64 prev_offset;
	u64 steps;
};

/* Client deserialization callback type */
typedef int (*blog_client_des_fn)(char *buf, size_t size, u8 client_id);

/* Core API functions - all require valid logger parameter */

/**
 * blog_get_source_id - Get or allocate a unique source ID for a log location
 * @logger: Logger instance to use
 * @file: Source file name (typically kbasename(__FILE__))
 * @func: Function name (typically __func__)
 * @line: Line number (typically __LINE__)
 * @fmt: Printf-style format string for this log site
 *
 * Assigns a unique source ID to a specific file:func:line location. The ID
 * is typically cached in a static variable at the call site for fast lookup.
 * The format string is stored in the logger's source map for later
 * deserialization.
 *
 * Context: Can be called from any context (process, softirq, hardirq)
 * Return: Source ID (1 to BLOG_MAX_SOURCE_IDS-1), or 0 on error
 */
u32 blog_get_source_id(struct blog_logger *logger, const char *file,
		       const char *func, unsigned int line, const char *fmt);

/**
 * blog_get_source_info - Retrieve source information for a given source ID
 * @logger: Logger instance to query
 * @id: Source ID to look up
 *
 * Retrieves the file, function, line, and format string associated with
 * a source ID. Used during deserialization to reconstruct log messages.
 *
 * Context: Any context
 * Return: Pointer to source_info structure, or NULL if ID is invalid
 */
struct blog_source_info *blog_get_source_info(struct blog_logger *logger,
					      u32 id);

/**
 * blog_log - Allocate buffer and log a binary message
 * @logger: Logger instance to use
 * @source_id: Source ID for this log location (from blog_get_source_id)
 * @client_id: Module-specific client identifier (0 if not used)
 * @needed_size: Size in bytes needed for serialized arguments
 *
 * Allocates space in the current context's pagefrag for a log entry and
 * returns a buffer pointer for the caller to serialize arguments into.
 * The log entry header (timestamp, source_id, etc.) is filled automatically.
 *
 * If allocation fails, the pagefrag is reset and retried up to 3 times.
 * Payload must not exceed BLOG_MAX_PAYLOAD (255 bytes).
 *
 * Context: Process or softirq (automatically selects appropriate context)
 * Return: Buffer pointer to write serialized data, or NULL on failure
 */
void *blog_log(struct blog_logger *logger, u32 source_id, u8 client_id,
	       size_t needed_size);

/**
 * blog_get_tls_ctx - Get or create per-task logging context
 * @logger: Logger instance to use
 *
 * Returns the BLOG context for the current task, creating it if needed.
 * Each task has a 512KB pagefrag buffer for logging. This function should
 * not be called directly - use blog_get_ctx() instead.
 *
 * Context: Process context only (uses current task)
 * Return: TLS context pointer, or NULL on allocation failure
 */
struct blog_tls_ctx *blog_get_tls_ctx(struct blog_logger *logger);

/**
 * blog_get_napi_ctx - Get NAPI logging context for current CPU
 * @logger: Logger instance to use
 *
 * Returns the NAPI (softirq) context for the current CPU. NAPI contexts
 * must be explicitly set via blog_set_napi_ctx() before use.
 *
 * Context: Softirq context
 * Return: NAPI context pointer, or NULL if not set
 */
struct blog_tls_ctx *blog_get_napi_ctx(struct blog_logger *logger);

/**
 * blog_set_napi_ctx - Set NAPI logging context for current CPU
 * @logger: Logger instance
 * @ctx: Context to associate with this CPU's NAPI processing
 *
 * Associates a logging context with the current CPU for use during
 * softirq (NAPI) processing. This allows network drivers and other
 * softirq handlers to log without accessing per-task contexts.
 *
 * Context: Any context (typically called during initialization)
 * Return: void
 */
void blog_set_napi_ctx(struct blog_logger *logger, struct blog_tls_ctx *ctx);

/**
 * blog_get_ctx - Get appropriate logging context based on execution context
 * @logger: Logger instance to use
 *
 * Automatically selects the correct context:
 * - Softirq context: Returns NAPI context (or falls back to TLS)
 * - Process context: Returns per-task TLS context
 *
 * This is the recommended function for getting contexts.
 *
 * Context: Any context
 * Return: Logging context pointer, or NULL on failure
 */
struct blog_tls_ctx *blog_get_ctx(struct blog_logger *logger);

/**
 * blog_log_trim - Reclaim unused space from last log entry
 * @logger: Logger instance
 * @n: Number of bytes to trim from the pagefrag
 *
 * Called when pre-allocated size was larger than actual serialized size.
 * Adjusts the pagefrag head pointer to reclaim unused space.
 *
 * Context: Same context as the preceding blog_log() call
 * Return: 0 on success, negative error code on failure
 */
int blog_log_trim(struct blog_logger *logger, unsigned int n);

/**
 * blog_log_iter_init - Initialize iterator for reading log entries
 * @iter: Iterator structure to initialize
 * @pf: Pagefrag containing log entries to iterate over
 *
 * Prepares an iterator to walk through all log entries in a pagefrag.
 * The pagefrag should not be modified while iteration is in progress.
 *
 * Context: Any context
 * Return: void
 */
void blog_log_iter_init(struct blog_log_iter *iter, struct blog_pagefrag *pf);

/**
 * blog_log_iter_next - Get next log entry from iterator
 * @iter: Iterator previously initialized with blog_log_iter_init()
 *
 * Advances the iterator to the next log entry in the pagefrag.
 * Entries are returned in chronological order (order they were logged).
 *
 * Context: Any context
 * Return: Pointer to next log entry, or NULL when no more entries
 */
struct blog_log_entry *blog_log_iter_next(struct blog_log_iter *iter);

/**
 * blog_des_entry - Deserialize a log entry into human-readable format
 * @logger: Logger instance (for source map lookup)
 * @entry: Log entry to deserialize
 * @output: Buffer to write formatted string to
 * @out_size: Size of output buffer in bytes
 * @client_cb: Optional callback to handle module-specific client_id formatting
 *
 * Reconstructs a formatted log message from binary log entry. Uses the
 * source_id to look up the format string, then deserializes the entry's
 * buffer according to the format specifiers.
 *
 * If client_cb is provided, it's called to format the client_id prefix.
 * Otherwise, client_id is ignored.
 *
 * Context: Any context
 * Return: Number of bytes written to output buffer, or negative error code
 */
int blog_des_entry(struct blog_logger *logger, struct blog_log_entry *entry, 
		   char *output, size_t out_size,
		   blog_client_des_fn client_cb);

/**
 * blog_logger_print_stats - Print logger statistics to kernel log
 * @logger: Logger instance to print stats for
 *
 * Debug helper that prints current state of logger's batching system
 * and context counts. Output goes to kernel log at debug level.
 *
 * Context: Any context
 * Return: void
 */
static inline void blog_logger_print_stats(struct blog_logger *logger)
{
	pr_debug(
		"blog: total_contexts=%lu, alloc_batch={empty=%d, full=%d}, log_batch={empty=%d, full=%d}\n",
		logger->total_contexts_allocated, logger->alloc_batch.nr_empty,
		logger->alloc_batch.nr_full, logger->log_batch.nr_empty,
		logger->log_batch.nr_full);
}

/**
 * blog_is_valid_kernel_addr - Check if address is in valid kernel range
 * @addr: Address to validate
 *
 * Verifies that an address points to valid kernel memory using
 * virt_addr_valid(). Used internally for sanity checking.
 *
 * Context: Any context
 * Return: true if address is valid, false otherwise
 */
bool blog_is_valid_kernel_addr(const void *addr);

/* 
 * No global logging macros - all logging must use per-module contexts
 * Use BLOG_LOG_CTX() and BLOG_LOG_CLIENT_CTX() from blog_module.h instead
 */

/*
 * These low-level logger macros are deprecated.
 * Use BLOG_LOG_CTX() and BLOG_LOG_CLIENT_CTX() from blog_module.h instead.
 */

#endif /* _LINUX_BLOG_H */
