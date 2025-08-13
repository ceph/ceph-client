/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ceph integration with BLOG (Binary LOGging)
 *
 * Provides compatibility layer and Ceph-specific extensions
 */
#ifndef CEPH_BLOG_H
#define CEPH_BLOG_H

#include <linux/blog/blog.h>
#include <linux/blog/blog_module.h>
#include <linux/ceph/libceph.h>

/* Client ID mapping structure - preserves ceph_san_client_id fields */
struct ceph_blog_client_info {
	char fsid[16];         /* Client FSID */
	u64 global_id;         /* Client global ID */
};

/* Constants */
#define CEPH_BLOG_MAX_CLIENTS 256

/* Ceph's BLOG module context */
extern struct blog_module_context *ceph_blog_ctx;

/* Ceph BLOG client management functions */
int ceph_blog_init(void);
void ceph_blog_cleanup(void);
u32 ceph_blog_check_client_id(u32 id, const char *fsid, u64 global_id);
u32 ceph_blog_get_client_id(struct ceph_client *client);
const struct ceph_blog_client_info *ceph_blog_get_client_info(u32 id);
int ceph_blog_client_des_callback(char *buf, size_t size, u8 client_id);

/* Compatibility macros for easy migration from ceph_san to BLOG */
#if defined(CONFIG_BLOG) || defined(CONFIG_BLOG_MODULE)

/* Direct mappings to BLOG functions */
#define ceph_san_logger_init()          blog_init()
#define ceph_san_logger_cleanup()       blog_cleanup()
#define ceph_san_get_source_id          blog_get_source_id
#define ceph_san_get_source_info        blog_get_source_info
#define ceph_san_log                    blog_log
#define ceph_san_get_tls_ctx()          blog_get_tls_ctx()
#define ceph_san_get_napi_ctx()         blog_get_napi_ctx()
#define ceph_san_set_napi_ctx(ctx)      blog_set_napi_ctx(ctx)
#define ceph_san_get_ctx()              blog_get_ctx()
#define ceph_san_log_trim               blog_log_trim

/* Structure mappings */
#define ceph_san_logger                 blog_logger
#define ceph_san_log_entry              blog_log_entry
#define ceph_san_tls_ctx                blog_tls_ctx
#define ceph_san_source_info            blog_source_info
#define ceph_san_log_iter               blog_log_iter

/* 
 * Ceph-specific logging macros - use Ceph's module context
 * Note: Only client-aware macros (doutc, boutc) store client_id,
 * regular macros (dout, bout) do not include client information
 */
#define CEPH_BLOG_LOG(fmt, ...) \
	do { \
		if (ceph_blog_ctx) \
			BLOG_LOG_CTX(ceph_blog_ctx, fmt, ##__VA_ARGS__); \
	} while (0)

#define CEPH_BLOG_LOG_CLIENT(client, fmt, ...) \
	do { \
		if (ceph_blog_ctx) { \
			u32 __client_id = ceph_blog_get_client_id(client); \
			BLOG_LOG_CLIENT_CTX(ceph_blog_ctx, __client_id, fmt, ##__VA_ARGS__); \
		} \
	} while (0)

/* Legacy compatibility - maps old ceph_san macros to BLOG */
/* Only define if not already defined by ceph_san_logger.h */
#ifndef CEPH_SAN_LOG
#define CEPH_SAN_LOG(fmt, ...) \
	CEPH_BLOG_LOG(fmt, ##__VA_ARGS__)
#endif

#ifndef CEPH_SAN_LOG_CLIENT
#define CEPH_SAN_LOG_CLIENT(client, fmt, ...) \
	CEPH_BLOG_LOG_CLIENT(client, fmt, ##__VA_ARGS__)
#endif

#else /* !CONFIG_BLOG */

/* Stub macros when BLOG is not enabled */
#define CEPH_BLOG_LOG(fmt, ...) do {} while (0)
#define CEPH_BLOG_LOG_CLIENT(client, fmt, ...) do {} while (0)
#define CEPH_SAN_LOG(fmt, ...) do {} while (0)
#define CEPH_SAN_LOG_CLIENT(client, fmt, ...) do {} while (0)

/* Stub functions should be static inline, not macros */
static inline int ceph_blog_init(void) { return 0; }
static inline void ceph_blog_cleanup(void) { }
static inline u32 ceph_blog_get_client_id(struct ceph_client *client) { return 0; }
static inline u32 ceph_blog_check_client_id(u32 id, const char *fsid, u64 global_id) { return 0; }
static inline const struct ceph_blog_client_info *ceph_blog_get_client_info(u32 id) { return NULL; }
static inline int ceph_blog_client_des_callback(char *buf, size_t size, u8 client_id) { return 0; }

#endif /* CONFIG_BLOG */

/* Debugfs support */
#ifdef CONFIG_DEBUG_FS
int ceph_blog_debugfs_init(struct dentry *parent);
void ceph_blog_debugfs_cleanup(void);
#else
static inline int ceph_blog_debugfs_init(struct dentry *parent) { return 0; }
static inline void ceph_blog_debugfs_cleanup(void) {}
#endif

#endif /* CEPH_BLOG_H */
