/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Per-superblock BLOG context and task-keyed rhashtable.
 */
#ifndef _FS_CEPH_BLOG_MODULE_H
#define _FS_CEPH_BLOG_MODULE_H

#include "blog.h"
#include <linux/rhashtable.h>
#include <linux/refcount.h>

struct blog_task_entry {
	struct rhash_head	node;
	struct task_struct	*task;
	pid_t			pid;
	char			comm[TASK_COMM_LEN];
	struct blog_tls_ctx	*ctx;
	unsigned long		flags;
	struct rcu_head		rcu;
};

struct blog_module_context {
	char name[32];
	struct blog_logger *logger;
	void *module_private;
	refcount_t refcount;
	atomic_t allocated_contexts;
	struct work_struct free_work;
	bool initialized;
};

struct blog_module_context *blog_module_init(const char *module_name);
void blog_module_put(struct blog_module_context *ctx);
void blog_module_flush_frees(void);
int blog_module_wq_init(void);
void blog_module_wq_exit(void);

struct blog_tls_ctx *blog_lookup_tls_ctx(struct blog_module_context *ctx);
struct blog_tls_ctx *blog_get_tls_ctx_ctx(struct blog_module_context *ctx,
					  gfp_t gfp);

#endif /* _FS_CEPH_BLOG_MODULE_H */
