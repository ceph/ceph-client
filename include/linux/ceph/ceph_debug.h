/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_CEPH_DEBUG_H
#define _FS_CEPH_DEBUG_H

#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/string.h>
#include <linux/ceph/ceph_blog.h>

#define CEPH_STRNCPY(dest, dest_len, src, src_len) ({     \
    size_t __len = (dest_len) - 1;                        \
    memcpy((dest), (src), min((size_t)(src_len), __len)); \
    (dest)[min((size_t)(src_len), __len)] = '\0';        \
})


#ifdef CONFIG_CEPH_LIB_PRETTYDEBUG

/*
 * wrap pr_debug to include a filename:lineno prefix on each line.
 * this incurs some overhead (kernel size and execution time) due to
 * the extra function call at each call site.
 */

# if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG)
#  define dout(fmt, ...)						\
	pr_debug("pid %d %.*s %12.12s:%-4d : " fmt,			\
		 current->pid,						\
		 8 - (int)sizeof(KBUILD_MODNAME), "    ",		\
		 kbasename(__FILE__), __LINE__, ##__VA_ARGS__)
#  define doutc(client, fmt, ...)					\
	pr_debug("pid %d %.*s %12.12s:%-4d %s() : [%pU %llu] " fmt,	\
		 current->pid,						\
		 8 - (int)sizeof(KBUILD_MODNAME), "    ",		\
		 kbasename(__FILE__), __LINE__, __func__,		\
		 &client->fsid, client->monc.auth->global_id,		\
		 ##__VA_ARGS__)
# else
/* faux printk call just to see any compiler warnings. */
#  define dout(fmt, ...)					\
		no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#  define doutc(client, fmt, ...)				\
		no_printk(KERN_DEBUG "[%pU %llu] " fmt,		\
			  &client->fsid,			\
			  client->monc.auth->global_id,		\
			  ##__VA_ARGS__)
# endif

#else

/*
 * or, just wrap pr_debug
 */
# define dout(fmt, ...)	pr_debug(" " fmt, ##__VA_ARGS__)
# define doutc(client, fmt, ...)					\
	pr_debug(" [%pU %llu] %s: " fmt, &client->fsid,			\
		 client->monc.auth->global_id, __func__, ##__VA_ARGS__)

#endif

#if defined(CONFIG_BLOG) || defined(CONFIG_BLOG_MODULE)
#define bout_dbg(fmt, ...)	\
	do { \
		CEPH_BLOG_LOG(fmt, ##__VA_ARGS__); \
	} while (0)

#define bout(fmt, ...)	\
	do { \
		CEPH_BLOG_LOG(fmt, ##__VA_ARGS__); \
	} while (0)

#define boutc(client, fmt, ...) \
	do { \
		CEPH_BLOG_LOG_CLIENT(client, fmt, ##__VA_ARGS__); \
	} while (0)
#else
#define bout_dbg(fmt, ...) do { } while (0)
#define bout(fmt, ...) do { } while (0)
#define boutc(client, fmt, ...) do { (void)(client); } while (0)
#endif

#define pr_notice_client(client, fmt, ...)				\
	pr_notice("[%pU %llu]: " fmt, &client->fsid,			\
		  client->monc.auth->global_id, ##__VA_ARGS__)
#define pr_info_client(client, fmt, ...)				\
	pr_info("[%pU %llu]: " fmt, &client->fsid,			\
		client->monc.auth->global_id, ##__VA_ARGS__)
#define pr_warn_client(client, fmt, ...)				\
	pr_warn("[%pU %llu]: " fmt, &client->fsid,			\
		client->monc.auth->global_id, ##__VA_ARGS__)
#define pr_warn_once_client(client, fmt, ...)				\
	pr_warn_once("[%pU %llu]: " fmt, &client->fsid,			\
		     client->monc.auth->global_id, ##__VA_ARGS__)
#define pr_err_client(client, fmt, ...)					\
	pr_err("[%pU %llu]: " fmt, &client->fsid,			\
	       client->monc.auth->global_id, ##__VA_ARGS__)
#define pr_warn_ratelimited_client(client, fmt, ...)			\
	pr_warn_ratelimited("[%pU %llu]: " fmt, &client->fsid,		\
			    client->monc.auth->global_id, ##__VA_ARGS__)
#define pr_err_ratelimited_client(client, fmt, ...)			\
	pr_err_ratelimited("[%pU %llu]: " fmt, &client->fsid,		\
			   client->monc.auth->global_id, ##__VA_ARGS__)

#endif
