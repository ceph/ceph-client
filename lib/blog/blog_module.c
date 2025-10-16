// SPDX-License-Identifier: GPL-2.0
/*
 * Binary Logging Infrastructure (BLOG) - Per-Module Support
 *
 * Implements per-module context management for isolated logging.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/bitops.h>
#include <linux/blog/blog.h>
#include <linux/blog/blog_module.h>

/* Global list of all module contexts */
static LIST_HEAD(blog_module_contexts);
static DEFINE_SPINLOCK(blog_modules_lock);

/* Global module registry */
static struct blog_module_registry blog_registry = {
	.modules = { NULL },
	.allocated_bitmap = 0,
	.lock = __SPIN_LOCK_UNLOCKED(blog_registry.lock),
	.module_count = ATOMIC_INIT(0),
};

/**
 * blog_module_register - Register a module and allocate a slot
 * @module_name: Name of the module
 *
 * Registers a module in the global registry and assigns it a slot ID (0-7).
 * The slot ID is used to index into each task's blog_contexts array.
 *
 * Return: Module context on success, NULL if no slots available
 */
struct blog_module_context *blog_module_register(const char *module_name)
{
	struct blog_module_context *ctx;
	unsigned long flags;
	int slot;
	size_t name_len;

	if (!module_name) {
		pr_err("blog: module name is NULL\n");
		return NULL;
	}

	name_len = strlen(module_name);
	if (name_len == 0) {
		pr_err("blog: module name is empty\n");
		return NULL;
	}
	
	if (name_len >= 32) {  /* sizeof(blog_module_context.name) */
		pr_err("blog: module name too long: '%s' (max 31 chars)\n",
		       module_name);
		return NULL;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	spin_lock_irqsave(&blog_registry.lock, flags);

	/* Find first free slot */
	slot = find_first_zero_bit((unsigned long *)&blog_registry.allocated_bitmap, 
				    BLOG_MAX_MODULES);
	if (slot >= BLOG_MAX_MODULES) {
		spin_unlock_irqrestore(&blog_registry.lock, flags);
		kfree(ctx);
		pr_err("blog: no free slots available (max %d modules)\n", 
		       BLOG_MAX_MODULES);
		return NULL;
	}

	/* Claim the slot */
	set_bit(slot, (unsigned long *)&blog_registry.allocated_bitmap);
	blog_registry.modules[slot] = ctx;
	atomic_inc(&blog_registry.module_count);

	spin_unlock_irqrestore(&blog_registry.lock, flags);

	/* Initialize the context */
	strscpy(ctx->name, module_name, sizeof(ctx->name));
	ctx->slot_id = slot;
	atomic_set(&ctx->refcount, 1);
	atomic_set(&ctx->allocated_contexts, 0);
	INIT_LIST_HEAD(&ctx->list);

	pr_info("blog: module '%s' registered with slot %d\n", module_name, slot);

	return ctx;
}
EXPORT_SYMBOL(blog_module_register);

/**
 * blog_module_unregister - Unregister a module and free its slot
 * @ctx: Module context to unregister
 *
 * Removes the module from the global registry and frees its slot.
 * Also cleans up any active task contexts for this module.
 */
void blog_module_unregister(struct blog_module_context *ctx)
{
	unsigned long flags;
	int slot;

	if (!ctx)
		return;

	slot = ctx->slot_id;
	if (slot >= BLOG_MAX_MODULES)
		goto out_free;

	spin_lock_irqsave(&blog_registry.lock, flags);
	if (test_bit(slot, (unsigned long *)&blog_registry.allocated_bitmap)) {
		clear_bit(slot, (unsigned long *)&blog_registry.allocated_bitmap);
		blog_registry.modules[slot] = NULL;
		atomic_dec(&blog_registry.module_count);
	}
	spin_unlock_irqrestore(&blog_registry.lock, flags);

	pr_info("blog: module '%s' unregistered from slot %d\n", ctx->name, slot);

out_free:
	kfree(ctx);
}
EXPORT_SYMBOL(blog_module_unregister);

/* Release hook for per-module TLS contexts */
static void blog_module_tls_release(void *ptr)
{
	struct blog_tls_ctx *ctx = ptr;

	if (!ctx)
		return;

	blog_pagefrag_deinit(&ctx->pf);
	kfree(ctx);
}

/**
 * blog_module_init - Initialize a per-module BLOG context
 * @module_name: Name of the module
 *
 * Creates an isolated logging context for a specific module.
 *
 * Return: Module context on success, NULL on failure
 */
struct blog_module_context *blog_module_init(const char *module_name)
{
	struct blog_module_context *ctx;
	struct blog_logger *logger;
	int i;
	int ret;

	ctx = blog_module_register(module_name);
	if (!ctx)
		return NULL;

	logger = kzalloc(sizeof(*logger), GFP_KERNEL);
	if (!logger)
		goto err_unregister;

	/* Initialize module context */
	strscpy(ctx->name, module_name, sizeof(ctx->name));
	ctx->logger = logger;
	atomic_set(&ctx->refcount, 1);
	INIT_LIST_HEAD(&ctx->list);

	/* Initialize logger instance */
	INIT_LIST_HEAD(&logger->contexts);
	spin_lock_init(&logger->lock);
	spin_lock_init(&logger->source_lock);
	spin_lock_init(&logger->ctx_id_lock);
	atomic_set(&logger->next_source_id, 1);
	logger->next_ctx_id = 1;
	logger->total_contexts_allocated = 0;

	/* Initialize batches */
	ret = blog_batch_init(&logger->alloc_batch);
	if (ret)
		goto err_logger;

	ret = blog_batch_init(&logger->log_batch);
	if (ret)
		goto err_batch_alloc;

	/* Initialize source map */
	for (i = 0; i < BLOG_MAX_SOURCE_IDS; i++) {
		memset(&logger->source_map[i], 0, sizeof(logger->source_map[i]));
	}

	/* Allocate per-CPU NAPI context pointers */
	logger->napi_ctxs = alloc_percpu(struct blog_tls_ctx *);
	if (!logger->napi_ctxs)
		goto err_batches;

	/* Add to global list */
	spin_lock(&blog_modules_lock);
	list_add(&ctx->list, &blog_module_contexts);
	spin_unlock(&blog_modules_lock);

	pr_info("BLOG: Module context initialized for %s\n", module_name);
	ctx->initialized = true;
	return ctx;

err_batches:
	blog_batch_cleanup(&logger->log_batch);
err_batch_alloc:
	blog_batch_cleanup(&logger->alloc_batch);
err_logger:
	kfree(logger);
err_unregister:
	blog_module_unregister(ctx);
	return NULL;
}
EXPORT_SYMBOL(blog_module_init);

/**
 * blog_module_cleanup - Clean up a module's BLOG context
 * @ctx: Module context to clean up
 */
void blog_module_cleanup(struct blog_module_context *ctx)
{
	struct blog_logger *logger;
	struct blog_tls_ctx *tls_ctx, *tmp;
	LIST_HEAD(pending);
	int slot;

	if (!ctx || !ctx->initialized)
		return;

	logger = ctx->logger;
	if (!logger)
		return;

	slot = ctx->slot_id;

	/* Remove from global list */
	spin_lock(&blog_modules_lock);
	list_del(&ctx->list);
	spin_unlock(&blog_modules_lock);

	/* Detach contexts under lock, release outside */
	spin_lock(&logger->lock);
	list_for_each_entry_safe(tls_ctx, tmp, &logger->contexts, list)
		list_move(&tls_ctx->list, &pending);
	spin_unlock(&logger->lock);

	list_for_each_entry_safe(tls_ctx, tmp, &pending, list) {
		struct task_struct *task = tls_ctx->task;

		list_del_init(&tls_ctx->list);
		if (task && slot < BLOG_MAX_MODULES) {
			task_lock(task);
			if (READ_ONCE(task->blog_contexts[slot]) == tls_ctx) {
				WRITE_ONCE(task->blog_contexts[slot], NULL);
			}
			task_unlock(task);
		}
		if (atomic_dec_if_positive(&ctx->allocated_contexts) < 0)
			atomic_set(&ctx->allocated_contexts, 0);
		tls_ctx->task = NULL;
		if (tls_ctx->release)
			tls_ctx->release(tls_ctx);
		else {
			blog_pagefrag_deinit(&tls_ctx->pf);
			kfree(tls_ctx);
		}
	}

	/* Clean up batches */
	blog_batch_cleanup(&logger->alloc_batch);
	blog_batch_cleanup(&logger->log_batch);

	/* Free per-CPU NAPI contexts */
	if (logger->napi_ctxs)
		free_percpu(logger->napi_ctxs);

	pr_info("BLOG: Module context cleaned up for %s\n", ctx->name);

	kfree(logger);
	ctx->logger = NULL;
	ctx->initialized = false;

	/* Unregister to free the slot */
	blog_module_unregister(ctx);
}
EXPORT_SYMBOL(blog_module_cleanup);

/**
 * blog_module_get - Increment module context reference count
 * @ctx: Module context
 */
void blog_module_get(struct blog_module_context *ctx)
{
	if (ctx)
		atomic_inc(&ctx->refcount);
}
EXPORT_SYMBOL(blog_module_get);

/**
 * blog_module_put - Decrement module context reference count
 * @ctx: Module context
 */
void blog_module_put(struct blog_module_context *ctx)
{
	if (ctx && atomic_dec_and_test(&ctx->refcount))
		blog_module_cleanup(ctx);
}
EXPORT_SYMBOL(blog_module_put);

/* Per-module API implementations */

/**
 * blog_get_source_id_ctx - Get or allocate source ID for a module context
 * @ctx: Module context
 * @file: Source file name
 * @func: Function name
 * @line: Line number
 * @fmt: Format string
 *
 * Return: Source ID
 */
u32 blog_get_source_id_ctx(struct blog_module_context *ctx, const char *file,
                           const char *func, unsigned int line, const char *fmt)
{
	struct blog_logger *logger;
	struct blog_source_info *info;
	u32 id;

	if (!ctx || !ctx->logger)
		return 0;

	logger = ctx->logger;

	/* Get next ID */
	id = atomic_fetch_inc(&logger->next_source_id);
	if (id >= BLOG_MAX_SOURCE_IDS) {
		pr_warn("BLOG: Source ID overflow in module %s\n", ctx->name);
		return 0;
	}

	/* Fill in source info */
	spin_lock(&logger->source_lock);
	info = &logger->source_map[id];
	info->file = file;
	info->func = func;
	info->line = line;
	info->fmt = fmt;
	info->warn_count = 0;
#if BLOG_TRACK_USAGE
	atomic_set(&info->napi_usage, 0);
	atomic_set(&info->task_usage, 0);
	atomic_set(&info->napi_bytes, 0);
	atomic_set(&info->task_bytes, 0);
#endif
	spin_unlock(&logger->source_lock);

	return id;
}
EXPORT_SYMBOL(blog_get_source_id_ctx);

/**
 * blog_get_source_info_ctx - Get source info for an ID in a module context
 * @ctx: Module context
 * @id: Source ID
 *
 * Return: Source info or NULL
 */
struct blog_source_info *blog_get_source_info_ctx(struct blog_module_context *ctx, u32 id)
{
	struct blog_logger *logger;

	if (!ctx || !ctx->logger || id >= BLOG_MAX_SOURCE_IDS)
		return NULL;

	logger = ctx->logger;
	return &logger->source_map[id];
}
EXPORT_SYMBOL(blog_get_source_info_ctx);

/**
 * blog_get_tls_ctx_ctx - Get or create TLS context for a module
 * @ctx: Module context
 *
 * Uses slot-based access into task_struct's blog_contexts array.
 *
 * Return: TLS context or NULL
 */
struct blog_tls_ctx *blog_get_tls_ctx_ctx(struct blog_module_context *ctx)
{
	struct blog_logger *logger;
	struct blog_tls_ctx *tls_ctx;
	struct task_struct *task = current;
	u8 slot_id;

	if (!ctx || !ctx->logger)
		return NULL;

	logger = ctx->logger;
	slot_id = ctx->slot_id;

	if (slot_id >= BLOG_MAX_MODULES) {
		pr_err("blog: invalid slot_id %d for module %s\n", slot_id, ctx->name);
		return NULL;
	}

	/* Fast path: check if context already exists */
	tls_ctx = READ_ONCE(task->blog_contexts[slot_id]);
	if (tls_ctx)
		return tls_ctx;

	/* Slow path: create new context */
	tls_ctx = kzalloc(sizeof(*tls_ctx), GFP_KERNEL);
	if (!tls_ctx)
		return NULL;

	/* Initialize TLS context */
	INIT_LIST_HEAD(&tls_ctx->list);
	atomic_set(&tls_ctx->refcount, 1);
	tls_ctx->task = task;
	tls_ctx->pid = task->pid;
	get_task_comm(tls_ctx->comm, task);
	tls_ctx->base_jiffies = jiffies;
	tls_ctx->release = blog_module_tls_release;

	/* Initialize pagefrag */
	blog_pagefrag_init(&tls_ctx->pf);

	/* Get unique context ID */
	spin_lock(&logger->ctx_id_lock);
	tls_ctx->id = logger->next_ctx_id++;
	spin_unlock(&logger->ctx_id_lock);

#if BLOG_DEBUG_POISON
	tls_ctx->debug_poison = BLOG_CTX_POISON;
#endif

	/* Add to logger's context list */
	spin_lock(&logger->lock);
	list_add(&tls_ctx->list, &logger->contexts);
	logger->total_contexts_allocated++;
	spin_unlock(&logger->lock);

	/* Install in task's context array - use cmpxchg for atomicity */
	if (cmpxchg(&task->blog_contexts[slot_id], NULL, tls_ctx) != NULL) {
		/* Another thread beat us to it */
		spin_lock(&logger->lock);
		list_del(&tls_ctx->list);
		logger->total_contexts_allocated--;
		spin_unlock(&logger->lock);
		blog_pagefrag_deinit(&tls_ctx->pf);
		kfree(tls_ctx);
		return task->blog_contexts[slot_id];
	}

	/* Context successfully installed */
	atomic_inc(&ctx->allocated_contexts);

	pr_debug("blog: created TLS context for module %s (slot %d), task %d [%s]\n",
		 ctx->name, slot_id, task->pid, task->comm);

	return tls_ctx;
}
EXPORT_SYMBOL(blog_get_tls_ctx_ctx);

/**
 * blog_log_ctx - Log a message with module context
 * @ctx: Module context
 * @source_id: Source ID
 * @client_id: Client ID
 * @needed_size: Size needed for the log entry
 *
 * Return: Buffer to write log data to, or NULL on failure
 */
void* blog_log_ctx(struct blog_module_context *ctx, u32 source_id, 
                   u8 client_id, size_t needed_size)
{
	struct blog_tls_ctx *tls_ctx;
	struct blog_log_entry *entry;
	int alloc;
	size_t total_size;

	if (!ctx || !ctx->logger)
		return NULL;

	/* Get TLS context */
	tls_ctx = blog_get_tls_ctx_ctx(ctx);
	if (!tls_ctx)
		return NULL;

	/* Validate payload size */
	if (needed_size > BLOG_MAX_PAYLOAD) {
		pr_warn_once("BLOG: payload too large (%zu > %u) in module %s\n",
		             needed_size, BLOG_MAX_PAYLOAD, ctx->name);
		return NULL;
	}

	/* Calculate total size needed */
	total_size = sizeof(*entry) + needed_size;

	/* Allocate space from pagefrag */
	alloc = blog_pagefrag_alloc(&tls_ctx->pf, total_size);
	if (alloc == -ENOMEM) {
		pr_debug("blog_log_ctx: allocation failed for module %s\n", ctx->name);
		blog_pagefrag_reset(&tls_ctx->pf);
		return NULL;
	}

	/* Get pointer from allocation */
	entry = blog_pagefrag_get_ptr(&tls_ctx->pf, alloc);
	if (!entry) {
		pr_err("blog_log_ctx: failed to get pointer from pagefrag\n");
		return NULL;
	}

	/* Fill in entry header */
#if BLOG_DEBUG_POISON
	entry->debug_poison = BLOG_LOG_ENTRY_POISON;
#endif
	entry->ts_delta = jiffies - tls_ctx->base_jiffies;
	entry->source_id = source_id;
	entry->len = (u8)needed_size;
	entry->client_id = client_id;
	entry->flags = 0;

	/* Return pointer to buffer area */
	return entry->buffer;
}
EXPORT_SYMBOL(blog_log_ctx);

/**
 * blog_log_trim_ctx - Trim unused space from last log entry
 * @ctx: Module context
 * @n: Number of bytes to trim
 *
 * Return: 0 on success, negative on error
 */
int blog_log_trim_ctx(struct blog_module_context *ctx, unsigned int n)
{
	struct blog_tls_ctx *tls_ctx;

	if (!ctx || !ctx->logger)
		return -EINVAL;

	tls_ctx = blog_get_tls_ctx_ctx(ctx);
	if (!tls_ctx)
		return -EINVAL;

	blog_pagefrag_trim(&tls_ctx->pf, n);
	return 0;
}
EXPORT_SYMBOL(blog_log_trim_ctx);

/**
 * blog_get_ctx_ctx - Get appropriate context based on execution context
 * @ctx: Module context
 *
 * Return: TLS context or NAPI context depending on execution context
 */
struct blog_tls_ctx *blog_get_ctx_ctx(struct blog_module_context *ctx)
{
	if (in_serving_softirq())
		return blog_get_napi_ctx_ctx(ctx);
	return blog_get_tls_ctx_ctx(ctx);
}
EXPORT_SYMBOL(blog_get_ctx_ctx);

/**
 * blog_get_napi_ctx_ctx - Get NAPI context for current CPU
 * @ctx: Module context
 *
 * Return: NAPI context or NULL
 */
struct blog_tls_ctx *blog_get_napi_ctx_ctx(struct blog_module_context *ctx)
{
	struct blog_logger *logger;
	struct blog_tls_ctx **napi_ctx_ptr;

	if (!ctx || !ctx->logger)
		return NULL;

	logger = ctx->logger;
	if (!logger->napi_ctxs)
		return NULL;

	/* Get pointer to the percpu pointer */
	napi_ctx_ptr = per_cpu_ptr(logger->napi_ctxs, smp_processor_id());
	return *napi_ctx_ptr;
}
EXPORT_SYMBOL(blog_get_napi_ctx_ctx);

/**
 * blog_set_napi_ctx_ctx - Set NAPI context for current CPU
 * @ctx: Module context
 * @tls_ctx: TLS context to set
 */
void blog_set_napi_ctx_ctx(struct blog_module_context *ctx, struct blog_tls_ctx *tls_ctx)
{
	struct blog_logger *logger;
	struct blog_tls_ctx **napi_ctx_ptr;

	if (!ctx || !ctx->logger || !ctx->logger->napi_ctxs)
		return;

	logger = ctx->logger;
	/* Get pointer to the percpu pointer and set it */
	napi_ctx_ptr = per_cpu_ptr(logger->napi_ctxs, smp_processor_id());
	*napi_ctx_ptr = tls_ctx;
}
EXPORT_SYMBOL(blog_set_napi_ctx_ctx);
