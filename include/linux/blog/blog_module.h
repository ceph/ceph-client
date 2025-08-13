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

/* Per-module context structure */
struct blog_module_context {
	char name[32];                      /* Module name */
	struct blog_logger *logger;         /* Logger instance for this module */
	void *module_private;               /* Module-specific private data */
	struct list_head list;              /* List of all module contexts */
	atomic_t refcount;                  /* Reference count */
	bool initialized;                   /* Initialization status */
};

/* Module context management API */
struct blog_module_context *blog_module_init(const char *module_name);
void blog_module_cleanup(struct blog_module_context *ctx);
void blog_module_get(struct blog_module_context *ctx);
void blog_module_put(struct blog_module_context *ctx);

/* Per-module API functions */
u32 blog_get_source_id_ctx(struct blog_module_context *ctx, const char *file, 
                           const char *func, unsigned int line, const char *fmt);
struct blog_source_info *blog_get_source_info_ctx(struct blog_module_context *ctx, u32 id);
void* blog_log_ctx(struct blog_module_context *ctx, u32 source_id, u8 client_id, size_t needed_size);
struct blog_tls_ctx *blog_get_tls_ctx_ctx(struct blog_module_context *ctx);
struct blog_tls_ctx *blog_get_napi_ctx_ctx(struct blog_module_context *ctx);
void blog_set_napi_ctx_ctx(struct blog_module_context *ctx, struct blog_tls_ctx *tls_ctx);
struct blog_tls_ctx *blog_get_ctx_ctx(struct blog_module_context *ctx);
int blog_log_trim_ctx(struct blog_module_context *ctx, unsigned int n);

/* Helper macros for per-module logging */
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

/* Per-module logging macros */
#define BLOG_LOG_CTX(ctx, fmt, ...) \
	__BLOG_LOG_CTX(ctx, 0, 0, fmt, ##__VA_ARGS__)

#define BLOG_LOG_CLIENT_CTX(ctx, client_id, fmt, ...) \
	__BLOG_LOG_CTX(ctx, 0, client_id, fmt, ##__VA_ARGS__)

#endif /* _LINUX_BLOG_MODULE_H */
