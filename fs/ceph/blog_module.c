// SPDX-License-Identifier: GPL-2.0
/*
 * Per-superblock BLOG context. Tasks map to TLS contexts via rhashtable.
 * Task references keep keys stable until exit reaping removes them.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/log2.h>
#include <linux/refcount.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/rhashtable.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "blog.h"
#include "blog_module.h"

static atomic64_t blog_logger_gen = ATOMIC64_INIT(1);
static struct workqueue_struct *blog_free_wq;

static void blog_module_free_workfn(struct work_struct *work);

#define BLOG_LOG_BATCH_MAX_FULL 16
#define BLOG_LOG_BATCH_MAX_FULL_CAP 1024
#define BLOG_MAX_TASK_CONTEXTS 64
#define BLOG_TASK_GC_INTERVAL (5 * HZ)
#define BLOG_TASK_ENTRY_RETIRED 0

static int blog_max_full = BLOG_LOG_BATCH_MAX_FULL;
module_param_named(blog_max_full, blog_max_full, int, 0644);
MODULE_PARM_DESC(blog_max_full,
		 "Visible full-magazine count for BLOG entries (default 16)");

static unsigned int blog_param_max_full(void)
{
	int n = READ_ONCE(blog_max_full);

	if (n < 1)
		n = 1;
	if (n > BLOG_LOG_BATCH_MAX_FULL_CAP)
		n = BLOG_LOG_BATCH_MAX_FULL_CAP;
	return n;
}

static const struct rhashtable_params blog_task_ht_params = {
	.key_offset = offsetof(struct blog_task_entry, task),
	.key_len = sizeof(struct task_struct *),
	.head_offset = offsetof(struct blog_task_entry, node),
	.automatic_shrinking = true,
};

static void blog_module_free_magazine(struct blog_logger *logger,
				      struct blog_magazine *mag)
{
	int i;

	for (i = 0; i < mag->count; i++)
		kvfree_atomic(mag->elements[i]);
	kmem_cache_free(logger->magazine_cache, mag);
}

static void blog_module_hide_magazine(struct blog_logger *logger,
				      struct blog_magazine *mag)
{
	struct blog_tls_pagefrag *composite;
	int i;

	spin_lock(&logger->lock);
	for (i = 0; i < mag->count; i++) {
		composite = mag->elements[i];
		if (!list_empty(&composite->ctx.list))
			list_del_init(&composite->ctx.list);
		/*
		 * Drop the publication ID on pool return so the next
		 * rotate/reuse takes a fresh monotonic ID.  Reusing the
		 * old ID lets blog_entries_show()'s cursor skip the
		 * newly published snapshot (silent loss) or reprint it.
		 */
		composite->ctx.id = 0;
	}
	spin_unlock(&logger->lock);
}

static void blog_module_rebalance_log_batch(struct blog_logger *logger)
{
	struct blog_magazine *mag;
	bool retain;

	if (!logger || logger->log_batch.nr_full <= blog_param_max_full())
		return;

	raw_spin_lock(&logger->log_batch.full_lock);
	if (list_empty(&logger->log_batch.full_magazines)) {
		raw_spin_unlock(&logger->log_batch.full_lock);
		return;
	}
	mag = list_first_entry(&logger->log_batch.full_magazines,
			       struct blog_magazine, list);
	list_del(&mag->list);
	logger->log_batch.nr_full--;
	raw_spin_unlock(&logger->log_batch.full_lock);

	/* Keep retained records visible until this magazine is reclaimed. */
	mutex_lock(&logger->snapshot_mutex);
	blog_module_hide_magazine(logger, mag);

	raw_spin_lock(&logger->alloc_batch.full_lock);
	retain = !logger->alloc_batch.retain_limit ||
		 logger->alloc_batch.nr_full * BLOG_MAGAZINE_SIZE <
		 logger->alloc_batch.retain_limit;
	if (retain) {
		list_add(&mag->list, &logger->alloc_batch.full_magazines);
		logger->alloc_batch.nr_full++;
	}
	raw_spin_unlock(&logger->alloc_batch.full_lock);
	if (!retain)
		blog_module_free_magazine(logger, mag);
	mutex_unlock(&logger->snapshot_mutex);
}

static void blog_module_schedule_log_reclaim(struct blog_logger *logger)
{
	if (logger && blog_free_wq && !READ_ONCE(logger->task_gc_stopping))
		queue_work(blog_free_wq, &logger->reclaim_work);
}

static void blog_module_reclaim_workfn(struct work_struct *work)
{
	struct blog_logger *logger =
		container_of(work, struct blog_logger, reclaim_work);
	LIST_HEAD(to_free);
	struct blog_tls_ctx *ctx, *tmp;
	bool again;

	mutex_lock(&logger->snapshot_mutex);
	spin_lock(&logger->lock);
	list_splice_init(&logger->reclaim_list, &to_free);
	spin_unlock(&logger->lock);

	list_for_each_entry_safe(ctx, tmp, &to_free, list) {
		list_del_init(&ctx->list);
		kvfree_atomic(blog_ctx_container(ctx));
	}
	mutex_unlock(&logger->snapshot_mutex);

	while (logger->log_batch.nr_full > blog_param_max_full())
		blog_module_rebalance_log_batch(logger);

	spin_lock(&logger->lock);
	again = !list_empty(&logger->reclaim_list);
	spin_unlock(&logger->lock);
	if (again)
		blog_module_schedule_log_reclaim(logger);
}

static void blog_module_queue_to_log_batch(struct blog_logger *logger,
					   struct blog_tls_ctx *ctx)
{
	struct blog_tls_pagefrag *composite;

	if (!logger || !ctx)
		return;

	/*
	 * Only task-map contexts are charged against allocated_contexts.
	 * Rotate-on-full snap buffers share this recycle path but were
	 * never counted. Do not let them underflow the 64-task cap.
	 */
	if (test_and_clear_bit(BLOG_CTX_TASK_COUNTED, &ctx->flags) &&
	    logger->owner_ctx)
		atomic_dec(&logger->owner_ctx->allocated_contexts);
	composite = blog_ctx_container(ctx);
	atomic_set(&ctx->refcount, 0);
	ctx->pending_offset = 0;
	ctx->pending_size = 0;
	if (!blog_batch_put(&logger->log_batch, composite)) {
		mutex_lock(&logger->snapshot_mutex);
		spin_lock(&logger->lock);
		if (!list_empty(&ctx->list))
			list_del_init(&ctx->list);
		spin_unlock(&logger->lock);
		kvfree_atomic(composite);
		mutex_unlock(&logger->snapshot_mutex);
	}
	blog_module_rebalance_log_batch(logger);
}

static void blog_module_clear_task(struct blog_tls_ctx *ctx)
{
	if (ctx) {
		ceph_blog_cpu_clear(ctx);
		WRITE_ONCE(ctx->task, NULL);
	}
}

static void blog_module_tls_release(void *ptr)
{
	struct blog_tls_ctx *ctx = ptr;
	struct blog_logger *logger;

	if (!ctx)
		return;
	logger = ctx->logger;
	if (!logger) {
		pr_err("BUG: TLS context id=%llu has no logger\n", ctx->id);
		return;
	}
	blog_module_clear_task(ctx);
	blog_module_queue_to_log_batch(logger, ctx);
}

/*
 * Retire a stale rhashtable entry: remove it from the hash table, retain its
 * TLS context on the reader-visible list while the log batch owns it, and
 * schedule the entry for RCU-deferred freeing.
 */
static bool blog_retire_entry_locked(struct blog_logger *logger,
				     struct blog_task_entry *entry,
				     struct blog_tls_ctx **tls_ctx)
{
	if (test_and_set_bit(BLOG_TASK_ENTRY_RETIRED, &entry->flags))
		return false;
	if (rhashtable_remove_fast(&logger->task_map, &entry->node,
				   blog_task_ht_params)) {
		clear_bit(BLOG_TASK_ENTRY_RETIRED, &entry->flags);
		return false;
	}

	*tls_ctx = entry->ctx;
	return true;
}

static bool blog_retire_stale_task(struct blog_logger *logger,
				   struct task_struct *task)
{
	struct blog_task_entry *entry;
	struct blog_tls_ctx *tls_ctx = NULL;
	bool retired = false;

	spin_lock(&logger->lock);
	rcu_read_lock();
	entry = rhashtable_lookup_fast(&logger->task_map, &task,
				       blog_task_ht_params);
	if (entry && entry->pid != task->pid)
		retired = blog_retire_entry_locked(logger, entry, &tls_ctx);
	rcu_read_unlock();
	spin_unlock(&logger->lock);

	if (tls_ctx) {
		blog_module_clear_task(tls_ctx);
		blog_module_queue_to_log_batch(logger, tls_ctx);
	}
	if (retired) {
		put_task_struct(entry->task);
		kfree_rcu(entry, rcu);
	}
	return retired;
}

static bool blog_retire_dead_task(struct blog_logger *logger,
				  struct task_struct *task, pid_t pid)
{
	struct blog_task_entry *entry;
	struct blog_tls_ctx *tls_ctx = NULL;
	bool retired = false;

	spin_lock(&logger->lock);
	rcu_read_lock();
	entry = rhashtable_lookup_fast(&logger->task_map, &task,
				       blog_task_ht_params);
	if (entry && entry->pid == pid && !pid_alive(entry->task))
		retired = blog_retire_entry_locked(logger, entry, &tls_ctx);
	rcu_read_unlock();
	spin_unlock(&logger->lock);

	if (tls_ctx) {
		blog_module_clear_task(tls_ctx);
		blog_module_queue_to_log_batch(logger, tls_ctx);
	}
	if (retired) {
		put_task_struct(entry->task);
		kfree_rcu(entry, rcu);
	}
	return retired;
}

struct blog_gc_item {
	struct list_head list;
	struct task_struct *task;
	pid_t pid;
};

static void blog_gc_dead_tasks(struct blog_logger *logger)
{
	struct rhashtable_iter iter;
	struct blog_task_entry *entry;
	struct blog_gc_item *item, *tmp;
	LIST_HEAD(dead);

	rhashtable_walk_enter(&logger->task_map, &iter);
	rhashtable_walk_start(&iter);
	for (;;) {
		entry = rhashtable_walk_next(&iter);
		if (IS_ERR(entry)) {
			if (PTR_ERR(entry) == -EAGAIN)
				continue;
			break;
		}
		if (!entry)
			break;
		if (!pid_alive(entry->task)) {
			item = kmalloc(sizeof(*item), GFP_ATOMIC);
			if (!item)
				continue;
			item->task = entry->task;
			item->pid = entry->pid;
			list_add_tail(&item->list, &dead);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	list_for_each_entry_safe(item, tmp, &dead, list) {
		blog_retire_dead_task(logger, item->task, item->pid);
		list_del(&item->list);
		kfree(item);
	}
}

static void blog_task_gc_workfn(struct work_struct *work)
{
	struct blog_logger *logger =
		container_of(to_delayed_work(work), struct blog_logger,
			     task_gc_work);

	blog_gc_dead_tasks(logger);
	if (!READ_ONCE(logger->task_gc_stopping))
		schedule_delayed_work(&logger->task_gc_work,
				      BLOG_TASK_GC_INTERVAL);
}

/*
 * Allocate a fresh TLS context (composite) from the magazine batch or
 * the page allocator, initialize it, and link it into the logger.
 */
static struct blog_tls_ctx *blog_alloc_tls_ctx(struct blog_logger *logger,
						 gfp_t gfp)
{
	struct blog_tls_pagefrag *composite;
	struct blog_tls_ctx *tls_ctx;
	struct blog_pagefrag *pf;
	struct task_struct *task = current;

	composite = blog_batch_get(&logger->alloc_batch);
	if (!composite)
		composite = kvzalloc(BLOG_TLS_PAGEFRAG_ALLOC_SIZE, gfp);
	if (!composite)
		return NULL;

	tls_ctx = &composite->ctx;

	if (tls_ctx->id == 0) {
		INIT_LIST_HEAD(&tls_ctx->list);
		spin_lock(&logger->ctx_id_lock);
		tls_ctx->id = logger->next_ctx_id++;
		spin_unlock(&logger->ctx_id_lock);
	}

	atomic_set(&tls_ctx->refcount, 1);
	tls_ctx->task = task;
	tls_ctx->pid = task->pid;
	get_task_comm(tls_ctx->comm, task);
	tls_ctx->base_jiffies = jiffies;
	tls_ctx->release = blog_module_tls_release;
	tls_ctx->logger = logger;
	tls_ctx->flags = 0;
	tls_ctx->pending_offset = 0;
	tls_ctx->pending_size = 0;
	WRITE_ONCE(tls_ctx->enter_depth, 0);
	WRITE_ONCE(tls_ctx->cache_cpu, -1);
	atomic64_set(&tls_ctx->clear_seq, atomic64_read(&logger->clear_seq));

	pf = &composite->pf;
	pf->buffer = composite->buf;
	pf->capacity = BLOG_TLS_PAGEFRAG_BUFFER_SIZE;
	spin_lock_init(&pf->lock);
	pf->head = 0;

	spin_lock(&logger->lock);
	if (list_empty(&tls_ctx->list)) {
		list_add(&tls_ctx->list, &logger->contexts);
		logger->total_contexts_allocated++;
	}
	spin_unlock(&logger->lock);

	return tls_ctx;
}

struct blog_module_context *blog_module_init(const char *module_name)
{
	struct blog_module_context *ctx;
	struct blog_logger *logger;
	char cache_name[48];
	int ret;

	if (!module_name || !*module_name)
		return NULL;
	if (strlen(module_name) >= sizeof(ctx->name))
		return NULL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	logger = kzalloc(sizeof(*logger), GFP_KERNEL);
	if (!logger)
		goto err_ctx;

	logger->generation = atomic64_inc_return(&blog_logger_gen);
	snprintf(cache_name, sizeof(cache_name), "blog_magazine_%llu",
		 (unsigned long long)logger->generation);
	logger->magazine_cache = kmem_cache_create(cache_name,
						   sizeof(struct blog_magazine),
						   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!logger->magazine_cache)
		goto err_logger;

	logger->max_source_ids = blog_param_max_sources();
	logger->source_map = kvcalloc(logger->max_source_ids,
				      sizeof(struct blog_source_info),
				      GFP_KERNEL);
	if (!logger->source_map)
		goto err_cache;

	{
		u32 hash_size = roundup_pow_of_two(logger->max_source_ids) * 2;

		if (hash_size < 4)
			hash_size = 4;
		logger->source_hash = kvcalloc(hash_size, sizeof(u32), GFP_KERNEL);
		if (!logger->source_hash)
			goto err_source_map;
		logger->source_hash_mask = hash_size - 1;
	}

	strscpy(ctx->name, module_name, sizeof(ctx->name));
	ctx->logger = logger;
	refcount_set(&ctx->refcount, 1);
	atomic_set(&ctx->allocated_contexts, 0);
	INIT_WORK(&ctx->free_work, blog_module_free_workfn);

	INIT_LIST_HEAD(&logger->contexts);
	INIT_LIST_HEAD(&logger->reclaim_list);
	spin_lock_init(&logger->lock);
	mutex_init(&logger->snapshot_mutex);
	spin_lock_init(&logger->source_lock);
	spin_lock_init(&logger->ctx_id_lock);
	logger->next_source_id = 1;
	logger->next_ctx_id = 1;
	logger->total_contexts_allocated = 0;
	logger->owner_ctx = ctx;
	atomic64_set(&logger->clear_seq, 0);
	INIT_DELAYED_WORK(&logger->task_gc_work, blog_task_gc_workfn);
	INIT_WORK(&logger->reclaim_work, blog_module_reclaim_workfn);
	logger->task_gc_stopping = false;

	ret = rhashtable_init(&logger->task_map, &blog_task_ht_params);
	if (ret)
		goto err_source_hash;

	ret = blog_batch_init(&logger->alloc_batch, logger->magazine_cache,
			      0,
			      num_possible_cpus() + 32);
	if (ret)
		goto err_ht;

	ret = blog_batch_init(&logger->log_batch, logger->magazine_cache, 0, 0);
	if (ret)
		goto err_batch_alloc;

	schedule_delayed_work(&logger->task_gc_work, BLOG_TASK_GC_INTERVAL);

	ctx->initialized = true;
	pr_debug("BLOG: module '%s' initialized\n", module_name);
	return ctx;

err_batch_alloc:
	blog_batch_cleanup(&logger->alloc_batch);
err_ht:
	rhashtable_destroy(&logger->task_map);
err_source_hash:
	kvfree(logger->source_hash);
err_source_map:
	kvfree(logger->source_map);
err_cache:
	kmem_cache_destroy(logger->magazine_cache);
err_logger:
	kfree(logger);
err_ctx:
	kfree(ctx);
	return NULL;
}

/*
 * Walk callback for rhashtable_free_and_destroy -- release each
 * task entry and its associated TLS context.
 */
static void blog_task_entry_free_cb(void *ptr, void *arg)
{
	struct blog_task_entry *entry = ptr;
	struct blog_logger *logger = arg;

	if (entry->ctx) {
		spin_lock(&logger->lock);
		if (!list_empty(&entry->ctx->list))
			list_del_init(&entry->ctx->list);
		spin_unlock(&logger->lock);

		blog_module_clear_task(entry->ctx);
		blog_module_queue_to_log_batch(logger, entry->ctx);
	}
	put_task_struct(entry->task);
	kfree(entry);
}

static void blog_module_free(struct blog_module_context *ctx)
{
	struct blog_logger *logger;
	struct blog_tls_ctx *tls_ctx, *tmp;
	LIST_HEAD(pending);
	LIST_HEAD(reclaim);

	if (!ctx || !ctx->initialized)
		return;
	logger = ctx->logger;
	if (!logger)
		return;

	WRITE_ONCE(logger->task_gc_stopping, true);
	cancel_delayed_work_sync(&logger->task_gc_work);
	cancel_work_sync(&logger->reclaim_work);

	rhashtable_free_and_destroy(&logger->task_map,
				    blog_task_entry_free_cb, logger);

	/* Detach retained log-batch contexts from the reader-visible list. */
	spin_lock(&logger->lock);
	list_for_each_entry_safe(tls_ctx, tmp, &logger->contexts, list)
		list_move(&tls_ctx->list, &pending);
	list_for_each_entry_safe(tls_ctx, tmp, &logger->reclaim_list, list)
		list_move(&tls_ctx->list, &reclaim);
	spin_unlock(&logger->lock);

	/* Failed atomic puts were never owned by log_batch. */
	list_for_each_entry_safe(tls_ctx, tmp, &reclaim, list) {
		list_del_init(&tls_ctx->list);
		kvfree_atomic(blog_ctx_container(tls_ctx));
	}

	list_for_each_entry_safe(tls_ctx, tmp, &pending, list) {
		list_del_init(&tls_ctx->list);
		if (!READ_ONCE(tls_ctx->task))
			continue;
		blog_module_clear_task(tls_ctx);
		if (tls_ctx->release)
			tls_ctx->release(tls_ctx);
		else
			blog_module_queue_to_log_batch(logger, tls_ctx);
	}

	/*
	 * rhashtable callbacks and the drain above can put into log_batch
	 * and, before task_gc_stopping, would re-queue reclaim_work.  Cancel
	 * again so a late queue cannot run after we free logger.
	 */
	cancel_work_sync(&logger->reclaim_work);

	blog_batch_cleanup(&logger->alloc_batch);
	blog_batch_cleanup(&logger->log_batch);

	if (logger->magazine_cache)
		kmem_cache_destroy(logger->magazine_cache);
	kvfree(logger->source_hash);
	kvfree(logger->source_map);

	pr_debug("BLOG: module '%s' cleaned up\n", ctx->name);

	kfree(logger);
	ctx->logger = NULL;
	ctx->initialized = false;
	kfree(ctx);
}

static void blog_module_free_workfn(struct work_struct *work)
{
	struct blog_module_context *ctx =
		container_of(work, struct blog_module_context, free_work);

	blog_module_free(ctx);
}

static void blog_discard_unmapped_ctx(struct blog_logger *logger,
				      struct blog_tls_ctx *tls_ctx)
{
	spin_lock(&logger->lock);
	if (!list_empty(&tls_ctx->list))
		list_del_init(&tls_ctx->list);
	spin_unlock(&logger->lock);

	blog_module_clear_task(tls_ctx);
	blog_module_queue_to_log_batch(logger, tls_ctx);
}

struct blog_tls_ctx *blog_lookup_tls_ctx(struct blog_module_context *ctx)
{
	struct blog_logger *logger;
	struct blog_task_entry *entry;
	struct blog_tls_ctx *tls_ctx = NULL;
	struct task_struct *task = current;

	if (!ctx || !ctx->logger)
		return NULL;
	logger = ctx->logger;

	rcu_read_lock();
	entry = rhashtable_lookup_fast(&logger->task_map, &task,
				       blog_task_ht_params);
	if (entry && entry->pid == task->pid)
		tls_ctx = entry->ctx;
	rcu_read_unlock();
	return tls_ctx;
}

struct blog_tls_ctx *blog_get_tls_ctx_ctx(struct blog_module_context *ctx,
					  gfp_t gfp)
{
	struct blog_logger *logger;
	struct blog_task_entry *entry;
	struct blog_tls_ctx *tls_ctx;
	struct task_struct *task = current;
	bool stale;
	int err;

	if (!ctx || !ctx->logger)
		return NULL;
	logger = ctx->logger;

	if (!gfpflags_allow_blocking(gfp))
		return blog_lookup_tls_ctx(ctx);

retry:
	tls_ctx = blog_lookup_tls_ctx(ctx);
	if (tls_ctx)
		return tls_ctx;

	rcu_read_lock();
	entry = rhashtable_lookup_fast(&logger->task_map, &task,
				       blog_task_ht_params);
	stale = entry && entry->pid != task->pid;
	rcu_read_unlock();

	if (stale) {
		if (!blog_retire_stale_task(logger, task))
			return NULL;
		goto retry;
	}

	entry = kzalloc(sizeof(*entry), gfp);
	if (!entry)
		return NULL;
	if (atomic_inc_return(&ctx->allocated_contexts) >
	    BLOG_MAX_TASK_CONTEXTS) {
		atomic_dec(&ctx->allocated_contexts);
		blog_gc_dead_tasks(logger);
		if (atomic_inc_return(&ctx->allocated_contexts) >
		    BLOG_MAX_TASK_CONTEXTS) {
			atomic_dec(&ctx->allocated_contexts);
			kfree(entry);
			return NULL;
		}
	}

	tls_ctx = blog_alloc_tls_ctx(logger, gfp);
	if (!tls_ctx) {
		atomic_dec(&ctx->allocated_contexts);
		kfree(entry);
		return NULL;
	}
	__set_bit(BLOG_CTX_TASK_COUNTED, &tls_ctx->flags);

	entry->task = task;
	entry->pid = task->pid;
	get_task_comm(entry->comm, task);
	entry->ctx = tls_ctx;
	entry->flags = 0;
	get_task_struct(task);

	err = rhashtable_lookup_insert_fast(&logger->task_map, &entry->node,
					    blog_task_ht_params);
	if (err) {
		put_task_struct(task);
		kfree(entry);
		blog_discard_unmapped_ctx(logger, tls_ctx);
		if (err != -EEXIST)
			return NULL;
		goto retry;
	}

	return tls_ctx;
}

void blog_module_put(struct blog_module_context *ctx)
{
	if (ctx && refcount_dec_and_test(&ctx->refcount)) {
		if (blog_free_wq)
			queue_work(blog_free_wq, &ctx->free_work);
		else
			blog_module_free(ctx);
	}
}

void blog_module_flush_frees(void)
{
	if (blog_free_wq)
		flush_workqueue(blog_free_wq);
}

int blog_module_wq_init(void)
{
	if (blog_free_wq)
		return 0;
	blog_free_wq = alloc_workqueue("ceph_blog_free",
				       WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	return blog_free_wq ? 0 : -ENOMEM;
}

void blog_module_wq_exit(void)
{
	if (!blog_free_wq)
		return;
	destroy_workqueue(blog_free_wq);
	blog_free_wq = NULL;
}

/*
 * Retire the live buffer's published records into a reader-visible
 * snapshot, then reset the live pagefrag so logging can continue.
 * Returns true if the snapshot is on the reader list.  Returns false if
 * allocation or log-batch put failed: live is left unpublished so the
 * caller can drop only the new record.
 *
 * blog/entries walks contexts by ascending ID.  The snapshot inherits
 * the live ID (older records) and live takes next_ctx_id (newer), so a
 * task's retired chunk sorts before its new tail.  Id swap and
 * contexts-list insertion happen under logger->lock *before* log_batch
 * put and before live head is cleared, so a concurrent dump cannot
 * advance past N while the snapshot is still invisible.  A dump may
 * briefly see the old bytes under the new live id (duplicate); that is
 * preferred to silently skipping the snapshot.
 *
 * Must not sleep: bout can run under GFP_ATOMIC enters.
 * Do not take snapshot_mutex here.
 */
static bool blog_retire_full_live_buffer(struct blog_logger *logger,
					 struct blog_tls_ctx *live)
{
	struct blog_tls_pagefrag *snap;
	struct blog_tls_ctx *snap_ctx;
	struct blog_pagefrag *live_pf = blog_ctx_pf(live);
	struct blog_pagefrag *snap_pf;
	unsigned int head;
	u64 new_live_id;

	snap = blog_batch_get(&logger->alloc_batch);
	if (!snap)
		snap = kvzalloc(BLOG_TLS_PAGEFRAG_ALLOC_SIZE, GFP_ATOMIC);
	if (!snap)
		return false;

	snap_ctx = &snap->ctx;
	if (snap_ctx->id == 0)
		INIT_LIST_HEAD(&snap_ctx->list);

	atomic_set(&snap_ctx->refcount, 0);
	snap_ctx->task = NULL;
	snap_ctx->pid = live->pid;
	memcpy(snap_ctx->comm, live->comm, sizeof(snap_ctx->comm));
	WRITE_ONCE(snap_ctx->base_jiffies, READ_ONCE(live->base_jiffies));
	snap_ctx->release = blog_module_tls_release;
	snap_ctx->logger = logger;
	snap_ctx->flags = 0;
	snap_ctx->pending_offset = 0;
	snap_ctx->pending_size = 0;
	WRITE_ONCE(snap_ctx->enter_depth, 0);
	atomic64_set(&snap_ctx->clear_seq, atomic64_read(&live->clear_seq));

	snap_pf = &snap->pf;
	snap_pf->buffer = snap->buf;
	snap_pf->capacity = BLOG_TLS_PAGEFRAG_BUFFER_SIZE;
	spin_lock_init(&snap_pf->lock);

	spin_lock(&live_pf->lock);
	head = live_pf->head;
	if (head)
		memcpy(snap->buf, live_pf->buffer, head);
	snap_pf->head = head;
	spin_unlock(&live_pf->lock);

	spin_lock(&logger->ctx_id_lock);
	new_live_id = logger->next_ctx_id++;
	spin_unlock(&logger->ctx_id_lock);

	/*
	 * Publish before put and before clearing live.  Otherwise a
	 * dump can copy live (id=N), verify id==N, advance the cursor,
	 * then miss the snapshot that later appears with id=N.
	 */
	spin_lock(&logger->lock);
	snap_ctx->id = live->id;
	live->id = new_live_id;
	if (list_empty(&snap_ctx->list)) {
		list_add(&snap_ctx->list, &logger->contexts);
		logger->total_contexts_allocated++;
	}
	spin_unlock(&logger->lock);

	if (!blog_batch_put(&logger->log_batch, snap)) {
		spin_lock(&logger->lock);
		/*
		 * Leave live->id at new_live_id.  Restoring the old id
		 * can hide this buffer behind a dump cursor that already
		 * walked past new_live_id.  The unused snap is reclaimed.
		 */
		snap_ctx->id = 0;
		if (!list_empty(&snap_ctx->list)) {
			list_del_init(&snap_ctx->list);
			if (logger->total_contexts_allocated)
				logger->total_contexts_allocated--;
		}
		list_add(&snap_ctx->list, &logger->reclaim_list);
		spin_unlock(&logger->lock);
		blog_module_schedule_log_reclaim(logger);
		return false;
	}

	spin_lock(&logger->lock);
	spin_lock(&live_pf->lock);
	smp_store_release(&live_pf->head, 0);
	spin_unlock(&live_pf->lock);
	spin_unlock(&logger->lock);

	blog_module_schedule_log_reclaim(logger);
	WRITE_ONCE(live->base_jiffies, jiffies);
	live->pending_offset = 0;
	live->pending_size = 0;
	return true;
}

/**
 * blog_log_with_ctx - Reserve buffer for a binary log message (explicit ctx)
 * @logger: Logger instance
 * @tls_ctx: TLS context to log into
 * @source_id: Source ID for this location
 * @client_id: Client ID for this message
 * @needed_size: Size needed for the message
 *
 * Only one reservation may be outstanding per context at a time.
 * The caller must call blog_log_commit_with_ctx() before issuing
 * another reservation on the same context.
 *
 * Returns a buffer to write the message into, or NULL on failure
 */
void *blog_log_with_ctx(struct blog_logger *logger,
			struct blog_tls_ctx *tls_ctx,
			u32 source_id, u8 client_id, size_t needed_size)
{
	struct blog_pagefrag *pf;
	struct blog_log_entry *entry;
	int alloc;
	size_t total_size;

	if (!logger || !tls_ctx)
		return NULL;

	if (needed_size > BLOG_MAX_PAYLOAD)
		return NULL;

	total_size = round_up(sizeof(*entry) + needed_size, 8);
	pf = blog_ctx_pf(tls_ctx);

	if (test_and_clear_bit(BLOG_CTX_NEEDS_RESET, &tls_ctx->flags) ||
	    atomic64_read(&tls_ctx->clear_seq) !=
	    atomic64_read(&logger->clear_seq)) {
		blog_pagefrag_reset(pf);
		tls_ctx->pending_offset = 0;
		tls_ctx->pending_size = 0;
		atomic64_set(&tls_ctx->clear_seq,
			     atomic64_read(&logger->clear_seq));
	}

	/*
	 * Records store jiffies - base_jiffies in a u32.  Long-lived
	 * lightly-logging tasks can exceed U32_MAX without a natural
	 * rotate; force one (or reset base) before the delta truncates.
	 */
	if (unlikely((jiffies - READ_ONCE(tls_ctx->base_jiffies)) > U32_MAX)) {
		if (pf->head) {
			if (!blog_retire_full_live_buffer(logger, tls_ctx)) {
				blog_pagefrag_reset(pf);
				tls_ctx->pending_offset = 0;
				tls_ctx->pending_size = 0;
				WRITE_ONCE(tls_ctx->base_jiffies, jiffies);
			}
		} else {
			WRITE_ONCE(tls_ctx->base_jiffies, jiffies);
		}
	}

	alloc = blog_pagefrag_reserve(pf, total_size);
	if (alloc == -ENOMEM) {
		/* Message larger than an empty buffer cannot fit after rotate. */
		if (!pf->head)
			return NULL;
		/*
		 * Retire failed (GFP_ATOMIC OOM or log-batch put): keep
		 * the full live window and drop only this record.  Do
		 * not wipe in place.
		 */
		if (!blog_retire_full_live_buffer(logger, tls_ctx)) {
			pr_warn_ratelimited(
				"blog: rotate-on-full alloc failed, dropping\n");
			return NULL;
		}
		alloc = blog_pagefrag_reserve(pf, total_size);
	}
	if (alloc < 0)
		return NULL;

	entry = blog_pagefrag_get_ptr(pf, alloc);
	if (!entry)
		return NULL;

	if (WARN_ON_ONCE(tls_ctx->pending_size != 0))
		return NULL;
	tls_ctx->pending_offset = alloc;
	tls_ctx->pending_size = total_size;

	entry->ts_delta = jiffies - READ_ONCE(tls_ctx->base_jiffies);
	entry->source_id = source_id;
	entry->len = 0;
	entry->client_id = client_id;
	entry->flags = 0;

	return entry->buffer;
}

int blog_log_commit_with_ctx(struct blog_logger *logger,
			     struct blog_tls_ctx *tls_ctx,
			     size_t actual_size)
{
	struct blog_pagefrag *pf;
	struct blog_log_entry *entry;
	size_t total_size;

	if (!logger || !tls_ctx)
		return -EINVAL;

	total_size = round_up(sizeof(struct blog_log_entry) + actual_size, 8);
	if (total_size > tls_ctx->pending_size) {
		tls_ctx->pending_offset = 0;
		tls_ctx->pending_size = 0;
		return -ENOSPC;
	}

	pf = blog_ctx_pf(tls_ctx);

	entry = blog_pagefrag_get_ptr(pf, tls_ctx->pending_offset);
	if (!entry) {
		tls_ctx->pending_offset = 0;
		tls_ctx->pending_size = 0;
		return -EFAULT;
	}
	entry->len = (u16)actual_size;

	blog_pagefrag_publish(pf, tls_ctx->pending_offset + total_size);
	tls_ctx->pending_offset = 0;
	tls_ctx->pending_size = 0;

	return 0;
}
