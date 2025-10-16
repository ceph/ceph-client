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

/* Ceph's logger - direct access to the logger for macros */
extern struct blog_logger *ceph_logger;

/* Forward declaration for ceph_client */
struct ceph_client;

/* Compatibility macros for easy migration from ceph_san to BLOG */
#if defined(CONFIG_BLOG) || defined(CONFIG_BLOG_MODULE)

/* Ceph BLOG client management functions */
int ceph_blog_init(void);
void ceph_blog_cleanup(void);
u32 ceph_blog_check_client_id(u32 id, const char *fsid, u64 global_id);
u32 ceph_blog_get_client_id(struct ceph_client *client);
const struct ceph_blog_client_info *ceph_blog_get_client_info(u32 id);
int ceph_blog_client_des_callback(char *buf, size_t size, u8 client_id);

/*
 * All ceph_san compatibility removed - use only BLOG with per-module contexts
 * CEPH_SAN has been replaced entirely by BLOG per-module logging
 */

/* 
 * Ceph-specific logging macros - use core BLOG functions with ceph_logger
 * Note: Only client-aware macros (doutc, boutc) store client_id,
 * regular macros (dout, bout) do not include client information
 */
#define CEPH_BLOG_LOG(fmt, ...) \
	do { \
		static u32 __source_id = 0; \
		static size_t __size = 0; \
		void *___buffer = NULL; \
		if (unlikely(!ceph_logger)) break; \
		if (unlikely(__source_id == 0)) { \
			__source_id = blog_get_source_id(ceph_logger, \
				kbasename(__FILE__), __func__, __LINE__, fmt); \
			__size = blog_cnt(__VA_ARGS__); \
		} \
		___buffer = blog_log(ceph_logger, __source_id, 0, __size); \
		if (likely(___buffer) && __size > 0) { \
			void *___tmp = ___buffer; \
			size_t actual_size; \
			blog_ser(___buffer, ##__VA_ARGS__); \
			actual_size = ___buffer - ___tmp; \
			blog_log_trim(ceph_logger, __size - actual_size); \
		} \
	} while (0)

#define CEPH_BLOG_LOG_CLIENT(client, fmt, ...) \
	do { \
		static u32 __source_id = 0; \
		static size_t __size = 0; \
		void *___buffer = NULL; \
		u32 __client_id; \
		if (unlikely(!ceph_logger)) break; \
		if (unlikely(__source_id == 0)) { \
			__source_id = blog_get_source_id(ceph_logger, \
				kbasename(__FILE__), __func__, __LINE__, fmt); \
			__size = blog_cnt(__VA_ARGS__); \
		} \
		__client_id = ceph_blog_get_client_id(client); \
		___buffer = blog_log(ceph_logger, __source_id, __client_id, __size); \
		if (likely(___buffer) && __size > 0) { \
			void *___tmp = ___buffer; \
			size_t actual_size; \
			blog_ser(___buffer, ##__VA_ARGS__); \
			actual_size = ___buffer - ___tmp; \
			blog_log_trim(ceph_logger, __size - actual_size); \
		} \
	} while (0)

/* No legacy ceph_san compatibility - use CEPH_BLOG_LOG* macros only */

#else /* !CONFIG_BLOG */

/* Stub macros when BLOG is not enabled */
#define CEPH_BLOG_LOG(fmt, ...) do {} while (0)
#define CEPH_BLOG_LOG_CLIENT(client, fmt, ...) do {} while (0)

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
