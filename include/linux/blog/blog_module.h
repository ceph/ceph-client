/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Binary Logging Infrastructure (BLOG) - Per-Module Support
 *
 * This header defines the per-module context support for BLOG.
 * Each kernel module can have its own isolated logging context.
 */
#ifndef _LINUX_BLOG_MODULE_H
#define _LINUX_BLOG_MODULE_H

#include <linux/blog/blog.h>

/**
 * struct blog_module_context - Per-module BLOG state
 * @name: Module name (max 31 chars + null terminator)
 * @slot_id: Assigned slot ID (0-7) in task->blog_contexts array
 * @logger: Logger instance for this module (isolated from other modules)
 * @module_private: Opaque pointer for module-specific data
 * @list: Linkage in global list of all module contexts
 * @refcount: Reference count for module context lifecycle
 * @allocated_contexts: Number of contexts currently allocated (includes freed but not yet recycled)
 * @initialized: True after blog_module_init() succeeds
 *
 * Represents a registered BLOG module with its own isolated logger instance,
 * slot ID for O(1) per-task context access, and independent source ID namespace.
 * Created via blog_module_init() and destroyed via blog_module_cleanup().
 */
struct blog_module_context {
	char name[32];
	u8 slot_id;
	struct blog_logger *logger;
	void *module_private;
	struct list_head list;
	atomic_t refcount;
	atomic_t allocated_contexts;
	bool initialized;
};

/**
 * struct blog_module_registry - Global registry of all BLOG modules
 * @modules: Array of registered module contexts (max 8)
 * @allocated_bitmap: Bitmap of allocated slot IDs (8 bits)
 * @lock: Protects registration/unregistration operations
 * @module_count: Number of currently registered modules
 *
 * Global singleton that tracks all registered BLOG modules and assigns
 * slot IDs. Protected by spinlock for thread-safe registration.
 */
struct blog_module_registry {
	struct blog_module_context *modules[BLOG_MAX_MODULES];
	u8 allocated_bitmap;
	spinlock_t lock;
	atomic_t module_count;
};

/* Module registration API */

/**
 * blog_module_register - Register a module and allocate a slot
 * @module_name: Name of the module (max 31 chars)
 *
 * Registers a module in the global BLOG registry and assigns it a unique
 * slot ID (0-7). The slot ID is used to index into each task's
 * blog_contexts array for O(1) per-task context access.
 *
 * Only 8 modules can be registered simultaneously (BLOG_MAX_MODULES).
 *
 * Context: Process context (uses GFP_KERNEL allocation)
 * Return: Module context on success, NULL if no slots available or invalid name
 */
struct blog_module_context *blog_module_register(const char *module_name);

/**
 * blog_module_unregister - Unregister a module and free its slot
 * @ctx: Module context to unregister
 *
 * Removes the module from the global registry and frees its slot for reuse.
 * Must be called after blog_module_cleanup() to ensure all contexts are freed.
 *
 * Context: Process context
 * Return: void
 */
void blog_module_unregister(struct blog_module_context *ctx);

/* Module context management API */

/**
 * blog_module_init - Initialize a per-module BLOG context
 * @module_name: Name of the module (max 31 chars)
 *
 * Creates a complete isolated logging context for a kernel module, including:
 * - Module registration and slot allocation
 * - Logger instance with batching system
 * - Source ID mapping (4096 sources)
 * - Per-CPU NAPI context support
 *
 * This is the main entry point for modules that want to use BLOG.
 *
 * Context: Process context (uses GFP_KERNEL allocations)
 * Return: Module context on success, NULL on failure
 */
struct blog_module_context *blog_module_init(const char *module_name);

/**
 * blog_module_cleanup - Clean up a module's BLOG context
 * @ctx: Module context to clean up
 *
 * Iterates through all tasks that have contexts for this module and
 * detaches/frees them. Also cleans up batching system and per-CPU
 * NAPI contexts. Should be called during module unload.
 *
 * Warning: This acquires task_lock for every task with a context, which
 * can be slow if many tasks are using the module.
 *
 * Context: Process context
 * Return: void
 */
void blog_module_cleanup(struct blog_module_context *ctx);

/**
 * blog_module_get - Increment module context reference count
 * @ctx: Module context
 *
 * Takes a reference on the module context to prevent it from being freed.
 * Must be paired with blog_module_put().
 *
 * Context: Any context
 * Return: void
 */
void blog_module_get(struct blog_module_context *ctx);

/**
 * blog_module_put - Decrement module context reference count
 * @ctx: Module context
 *
 * Releases a reference on the module context. When the last reference
 * is dropped, the context is automatically cleaned up.
 *
 * Context: Any context
 * Return: void
 */
void blog_module_put(struct blog_module_context *ctx);

/* Per-module API functions */

/**
 * blog_get_source_id_ctx - Get source ID for a module's log location
 * @ctx: Module context
 * @file: Source file name (typically kbasename(__FILE__))
 * @func: Function name (typically __func__)
 * @line: Line number (typically __LINE__)
 * @fmt: Printf-style format string
 *
 * Per-module wrapper around blog_get_source_id(). Source IDs are
 * module-local (different modules can have same source_id values).
 *
 * Context: Any context
 * Return: Source ID for this module's logger, or 0 on error
 */
u32 blog_get_source_id_ctx(struct blog_module_context *ctx, const char *file, 
                           const char *func, unsigned int line, const char *fmt);

/**
 * blog_get_source_info_ctx - Get source info for a module-local source ID
 * @ctx: Module context
 * @id: Source ID to look up
 *
 * Per-module wrapper around blog_get_source_info().
 *
 * Context: Any context
 * Return: Source info pointer, or NULL if invalid
 */
struct blog_source_info *blog_get_source_info_ctx(struct blog_module_context *ctx, u32 id);

/**
 * blog_log_ctx - Log a message using module context
 * @ctx: Module context
 * @source_id: Source ID (from blog_get_source_id_ctx)
 * @client_id: Module-specific client identifier
 * @needed_size: Size in bytes for serialized arguments
 *
 * Per-module wrapper around blog_log(). Uses the module's slot ID to
 * access the per-task context from task->blog_contexts[slot_id].
 *
 * Context: Process or softirq
 * Return: Buffer pointer for serialization, or NULL on failure
 */
void* blog_log_ctx(struct blog_module_context *ctx, u32 source_id, u8 client_id, size_t needed_size);

/**
 * blog_get_tls_ctx_ctx - Get or create per-task context for this module
 * @ctx: Module context
 *
 * Gets the logging context for current task and this specific module.
 * Uses slot-based access: task->blog_contexts[ctx->slot_id].
 * Creates the context on first use (lazy allocation).
 *
 * Context: Process context only
 * Return: TLS context pointer, or NULL on allocation failure
 */
struct blog_tls_ctx *blog_get_tls_ctx_ctx(struct blog_module_context *ctx);

/**
 * blog_get_napi_ctx_ctx - Get NAPI context for this module
 * @ctx: Module context
 *
 * Returns the NAPI (softirq) context for current CPU and this module.
 *
 * Context: Softirq context
 * Return: NAPI context pointer, or NULL if not set
 */
struct blog_tls_ctx *blog_get_napi_ctx_ctx(struct blog_module_context *ctx);

/**
 * blog_set_napi_ctx_ctx - Set NAPI context for this module
 * @ctx: Module context
 * @tls_ctx: Context to use for NAPI on current CPU
 *
 * Associates a context with current CPU for softirq logging.
 *
 * Context: Any context
 * Return: void
 */
void blog_set_napi_ctx_ctx(struct blog_module_context *ctx, struct blog_tls_ctx *tls_ctx);

/**
 * blog_get_ctx_ctx - Get appropriate context for this module
 * @ctx: Module context
 *
 * Automatically selects NAPI or TLS context based on execution context.
 * This is the recommended function for per-module context access.
 *
 * Context: Any context
 * Return: Context pointer, or NULL on failure
 */
struct blog_tls_ctx *blog_get_ctx_ctx(struct blog_module_context *ctx);

/**
 * blog_log_trim_ctx - Trim unused space from last log entry
 * @ctx: Module context
 * @n: Number of bytes to trim
 *
 * Per-module wrapper around blog_log_trim().
 *
 * Context: Same context as preceding blog_log_ctx() call
 * Return: 0 on success, negative error code on failure
 */
int blog_log_trim_ctx(struct blog_module_context *ctx, unsigned int n);

/*
 * Per-module logging macros
 *
 * These macros provide the primary logging interface for modules using BLOG.
 * They handle source ID caching, size calculation, serialization, and trimming
 * automatically.
 */

/**
 * BLOG_LOG_CTX - Log a message using module context (no client ID)
 * @ctx: Module context from blog_module_init()
 * @fmt: Printf-style format string
 * @...: Arguments matching format string
 *
 * Primary logging macro for per-module BLOG usage. Automatically handles:
 * - Source ID allocation and caching (static variable per call site)
 * - Size calculation at compile time
 * - Context acquisition (task or NAPI)
 * - Serialization of arguments
 * - Trimming of unused space
 *
 * Example:
 *   BLOG_LOG_CTX(my_module_ctx, "Processing inode %llu size %zu\n", 
 *                inode_num, size);
 *
 * Context: Any context (automatically selects task or NAPI context)
 */
#define BLOG_LOG_CTX(ctx, fmt, ...) \
	__BLOG_LOG_CTX(ctx, 0, 0, fmt, ##__VA_ARGS__)

/**
 * BLOG_LOG_CLIENT_CTX - Log a message with client identifier
 * @ctx: Module context from blog_module_init()
 * @client_id: Module-specific client identifier (e.g., connection ID)
 * @fmt: Printf-style format string
 * @...: Arguments matching format string
 *
 * Like BLOG_LOG_CTX but includes a client_id in the log entry. The client_id
 * is module-specific and can be used to associate logs with specific clients,
 * connections, or sessions.
 *
 * Example:
 *   BLOG_LOG_CLIENT_CTX(ceph_ctx, ceph_client_id, 
 *                       "Cap update for inode %llu\n", inode);
 *
 * During deserialization, the module's client callback is invoked to
 * format the client_id (e.g., "[fsid global_id]" prefix).
 *
 * Context: Any context (automatically selects task or NAPI context)
 */
#define BLOG_LOG_CLIENT_CTX(ctx, client_id, fmt, ...) \
	__BLOG_LOG_CTX(ctx, 0, client_id, fmt, ##__VA_ARGS__)

/* Internal implementation - do not use directly */
#define __BLOG_LOG_CTX(__ctx, dbg, __client_id, fmt, ...) \
	do { \
		static u32 __source_id = 0; \
		static size_t __size = 0; \
		void *___buffer = NULL; \
		if (unlikely(__source_id == 0)) { \
			__source_id = blog_get_source_id_ctx(__ctx, kbasename(__FILE__), __func__, __LINE__, fmt); \
			__size = blog_cnt(__VA_ARGS__); \
		} \
		___buffer = blog_log_ctx(__ctx, __source_id, __client_id, __size); \
		if (likely(___buffer) && __size > 0) {	\
			void *___tmp = ___buffer; \
			size_t actual_size; \
			blog_ser(___buffer, ##__VA_ARGS__);\
			actual_size = ___buffer - ___tmp; \
			blog_log_trim_ctx(__ctx, __size - actual_size); \
		} \
	} while (0)

#endif /* _LINUX_BLOG_MODULE_H */
