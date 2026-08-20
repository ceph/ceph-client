/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_CEPH_DEBUG_H
#define _FS_CEPH_DEBUG_H

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/string.h>
#include <linux/jump_label.h>

#ifdef CONFIG_CEPH_LIB_PRETTYDEBUG

# if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG)
#  define dout(fmt, ...)						\
	pr_debug("%.*s %12.12s:%-4d : " fmt,				\
		 8 - (int)sizeof(KBUILD_MODNAME), "    ",		\
		 kbasename(__FILE__), __LINE__, ##__VA_ARGS__)
#  define doutc(client, fmt, ...)					\
	pr_debug("%.*s %12.12s:%-4d : [%pU %llu] " fmt,		\
		 8 - (int)sizeof(KBUILD_MODNAME), "    ",		\
		 kbasename(__FILE__), __LINE__,				\
		 &client->fsid, client->monc.auth->global_id,		\
		 ##__VA_ARGS__)
# else
#  define dout(fmt, ...)					\
		no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#  define doutc(client, fmt, ...)				\
		no_printk(KERN_DEBUG "[%pU %llu] " fmt,		\
			  &client->fsid,			\
			  client->monc.auth->global_id,		\
			  ##__VA_ARGS__)
# endif

#else

# define dout(fmt, ...)	pr_debug(" " fmt, ##__VA_ARGS__)
# define doutc(client, fmt, ...)					\
	pr_debug(" [%pU %llu] %s: " fmt, &client->fsid,		\
		 client->monc.auth->global_id, __func__, ##__VA_ARGS__)

#endif

/*
 * boutc* -- binary-logging variants of doutc*.
 *
 * When Ceph BLOG tracing has been explicitly enabled and a BLOG context
 * has been bound for the current task (via ceph_blog_enter()),
 * these route through the BLOG serialization path. Otherwise they fall
 * back to the traditional text-based doutc macros so that existing
 * debug semantics remain unchanged.
 *
 * Must only be used from fs/ceph/ where client->private is a
 * ceph_fs_client *.  Do not call from net/ceph or RBD; ->private is not
 * an fsc there (ceph_blog_key stays false, but the cast is still wrong).
 */
#define __ceph_blog_args(...) __VA_ARGS__
#if IS_ENABLED(CONFIG_CEPH_FS) && IS_ENABLED(CONFIG_DEBUG_FS)
# include <linux/ceph/ceph_blog.h>
# define boutc(client, fmt, ...) \
	do { \
		if (static_branch_unlikely(&ceph_blog_key)) { \
			struct blog_tls_ctx *__ctx = ceph_blog_get_cached_ctx( \
				(struct ceph_fs_client *)(client)->private); \
			if (__ctx) \
				CEPH_BLOG_LOG_CLIENT(__ctx, client, fmt, ##__VA_ARGS__); \
			else \
				doutc(client, fmt, ##__VA_ARGS__); \
		} else \
			doutc(client, fmt, ##__VA_ARGS__); \
	} while (0)
# define boutc_bounded(client, fmt, blog_args, text_args) \
	do { \
		if (static_branch_unlikely(&ceph_blog_key)) { \
			struct blog_tls_ctx *__ctx = ceph_blog_get_cached_ctx( \
				(struct ceph_fs_client *)(client)->private); \
			if (__ctx) \
				CEPH_BLOG_LOG_CLIENT(__ctx, client, fmt, \
						     __ceph_blog_args blog_args); \
			else \
				doutc(client, fmt, __ceph_blog_args text_args); \
		} else \
			doutc(client, fmt, __ceph_blog_args text_args); \
	} while (0)
# define boutc_formats(client, blog_fmt, text_fmt, blog_args, text_args) \
	do { \
		if (static_branch_unlikely(&ceph_blog_key)) { \
			struct blog_tls_ctx *__ctx = ceph_blog_get_cached_ctx( \
				(struct ceph_fs_client *)(client)->private); \
			if (__ctx) \
				CEPH_BLOG_LOG_CLIENT(__ctx, client, blog_fmt, \
						     __ceph_blog_args blog_args); \
			else \
				doutc(client, text_fmt, __ceph_blog_args text_args); \
		} else \
			doutc(client, text_fmt, __ceph_blog_args text_args); \
	} while (0)
#else
# define boutc(client, fmt, ...) doutc(client, fmt, ##__VA_ARGS__)
# define boutc_bounded(client, fmt, blog_args, text_args) \
	do { \
		(void)sizeof(#blog_args); \
		doutc(client, fmt, __ceph_blog_args text_args); \
	} while (0)
# define boutc_formats(client, blog_fmt, text_fmt, blog_args, text_args) \
	do { \
		(void)sizeof(blog_fmt); \
		(void)sizeof(#blog_args); \
		doutc(client, text_fmt, __ceph_blog_args text_args); \
	} while (0)
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
