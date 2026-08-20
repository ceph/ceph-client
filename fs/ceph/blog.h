/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CephFS binary logging (BLOG) private types.
 */
#ifndef _FS_CEPH_BLOG_H
#define _FS_CEPH_BLOG_H

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/rhashtable-types.h>
#include <linux/ceph/ceph_blog.h>
#include "blog_batch.h"
#include "blog_pagefrag.h"
#include "blog_ser.h"
#include "blog_des.h"

struct blog_module_context;

/* Absolute caps for module parameters (load-time only). */
#define BLOG_MAX_SOURCE_IDS_CAP	65535
#define BLOG_MAX_CLIENT_IDS_CAP	256
#define BLOG_DEFAULT_MAX_SOURCES 4096
#define BLOG_DEFAULT_MAX_CLIENTS 256
#define BLOG_MAX_PAYLOAD U16_MAX

struct blog_source_info {
	const char *file;
	const char *func;
	unsigned int line;
	const char *fmt;
	int warn_count;
};

struct blog_log_entry {
	u32 ts_delta;
	u16 source_id;
	u16 len;
	u8 client_id;
	u8 flags;
	char buffer[];
};

#define BLOG_CTX_NEEDS_RESET	0
#define BLOG_CTX_TASK_COUNTED	1

struct blog_tls_ctx {
	struct list_head list;
	void (*release)(void *data);
	atomic_t refcount;
	struct task_struct *task;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	u64 id;
	unsigned long base_jiffies;
	struct blog_logger *logger;
	int pending_offset;
	size_t pending_size;
	unsigned long flags;
	/* Nested ceph_blog_enter* depth for this task; bout uses CPU cache only while > 0. */
	unsigned int enter_depth;
	/* CPU whose per-CPU cache slot bind published; unbind clears it after migration. */
	int cache_cpu;
	/* Matches logger->clear_seq after a reset; readers treat mismatch as empty. */
	atomic64_t clear_seq;
};

struct blog_tls_pagefrag {
	struct blog_tls_ctx ctx;
	struct blog_pagefrag pf;
	unsigned char buf[];
};

#define BLOG_TLS_PAGEFRAG_ALLOC_SIZE BLOG_PAGEFRAG_SIZE
#define BLOG_TLS_PAGEFRAG_BUFFER_SIZE \
	(BLOG_PAGEFRAG_SIZE - sizeof(struct blog_tls_pagefrag))

struct blog_logger {
	struct list_head contexts;
	spinlock_t lock;
	struct mutex snapshot_mutex;
	struct rhashtable task_map;
	struct blog_batch alloc_batch;
	struct blog_batch log_batch;
	struct kmem_cache *magazine_cache;
	struct blog_source_info *source_map;
	u32 *source_hash;	/* open-addressed, stores source IDs (0 = empty) */
	u32 source_hash_mask;
	u32 max_source_ids;
	u32 next_source_id;	/* serialized by source_lock */
	spinlock_t source_lock;
	unsigned long total_contexts_allocated;
	u64 next_ctx_id;
	spinlock_t ctx_id_lock;
	struct blog_module_context *owner_ctx;
	u64 generation;
	/* Bumped by debugfs "clear"; writers/readers sync via ctx->clear_seq. */
	atomic64_t clear_seq;
	struct delayed_work task_gc_work;
	bool task_gc_stopping;
	/*
	 * Atomic rotate (bout under spinlock) cannot take snapshot_mutex.
	 * Failed log-batch puts land on reclaim_list; reclaim_work drains
	 * them and rebalances under sleepable context.
	 */
	struct list_head reclaim_list;
	struct work_struct reclaim_work;
};

/**
 * struct blog_source_id_cache - per-callsite source ID fast cache
 * @logger: logger that owns the cached ID
 * @generation: logger generation at cache-fill time
 * @id: cached source ID (0 = not yet cached)
 * @seq: validates lockless cache snapshots
 * @lock: serializes cache updates shared by all mounts
 */
struct blog_source_id_cache {
	struct blog_logger *logger;
	u64 generation;
	u32 id;
	seqcount_spinlock_t seq;
	spinlock_t lock;
};

#define BLOG_SOURCE_ID_CACHE_INIT(name) { \
	.seq = SEQCNT_SPINLOCK_ZERO(name.seq, &(name).lock), \
	.lock = __SPIN_LOCK_UNLOCKED(name.lock), \
}

struct blog_log_iter {
	struct blog_pagefrag *pf;
	u64 current_offset;
	u64 end_offset;
	u64 prev_offset;
	u64 steps;
};

typedef int (*blog_client_des_fn)(char *buf, size_t size, u8 client_id);

int blog_param_max_sources(void);
int blog_param_max_clients(void);

u32 blog_get_source_id(struct blog_logger *logger, const char *file,
		       const char *func, unsigned int line, const char *fmt);
u32 blog_get_source_id_cached(struct blog_logger *logger,
			      struct blog_source_id_cache *cache,
			      const char *file, const char *func,
			      unsigned int line, const char *fmt);
struct blog_source_info *blog_get_source_info(struct blog_logger *logger,
					      u32 id);
void blog_log_iter_init(struct blog_log_iter *iter, struct blog_pagefrag *pf,
			u64 head_snapshot);
struct blog_log_entry *blog_log_iter_next(struct blog_log_iter *iter);
int blog_des_entry(struct blog_logger *logger, struct blog_log_entry *entry,
		   char *output, size_t out_size,
		   blog_client_des_fn client_cb);
void *blog_log_with_ctx(struct blog_logger *logger,
			struct blog_tls_ctx *tls_ctx,
			u32 source_id, u8 client_id, size_t needed_size);
int blog_log_commit_with_ctx(struct blog_logger *logger,
			     struct blog_tls_ctx *tls_ctx,
			     size_t actual_size);
static inline struct blog_tls_pagefrag *blog_ctx_container(struct blog_tls_ctx *ctx)
{
	return container_of(ctx, struct blog_tls_pagefrag, ctx);
}

static inline struct blog_pagefrag *blog_ctx_pf(struct blog_tls_ctx *ctx)
{
	return &blog_ctx_container(ctx)->pf;
}

#define CEPH_BLOG_LOG_CLIENT(ctx, client, fmt, ...) \
	do { \
		static struct blog_source_id_cache __source_cache = \
			BLOG_SOURCE_ID_CACHE_INIT(__source_cache); \
		struct blog_tls_ctx *__blog_ctx = (ctx); \
		struct blog_logger *__logger; \
		if (unlikely(!__blog_ctx)) \
			break; \
		__logger = __blog_ctx->logger; \
		if (unlikely(!__logger)) \
			break; \
		{ \
			struct blog_arg __args[blog_narg(__VA_ARGS__) ?: 1] = { \
				BLOG_ARGS(__VA_ARGS__) \
			}; \
			size_t __nargs = blog_narg(__VA_ARGS__); \
			size_t __size = blog_args_size(__args, __nargs); \
			void *___buffer; \
			u32 __client_id; \
			u32 __sid; \
			__sid = blog_get_source_id_cached(__logger, \
					&__source_cache, \
					kbasename(__FILE__), __func__, \
					__LINE__, fmt); \
			if (unlikely(__sid == 0)) \
				break; \
			__client_id = ceph_blog_get_client_id(client); \
			___buffer = blog_log_with_ctx(__logger, __blog_ctx, \
						      __sid, __client_id, \
						      __size); \
			if (likely(___buffer)) { \
				void *___tmp = ___buffer; \
				___buffer = blog_serialize_args(___buffer, \
						__args, __nargs); \
				blog_log_commit_with_ctx(__logger, __blog_ctx, \
						___buffer - ___tmp); \
			} \
		} \
	} while (0)

#endif /* _FS_CEPH_BLOG_H */
