// SPDX-License-Identifier: GPL-2.0
/*
 * Binary Logging Infrastructure - Core Implementation
 *
 * Migrated from ceph_san_logger.c with algorithms preserved
 * Client ID management removed - modules handle their own mappings
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/time.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>

#include <linux/blog/blog.h>
#include <linux/blog/blog_batch.h>
#include <linux/blog/blog_pagefrag.h>
#include <linux/blog/blog_ser.h>
#include <linux/blog/blog_des.h>

static void blog_tls_release_verbose(void *ptr);
#define NULL_STR "(NULL)"
#define BLOG_LOG_BATCH_MAX_FULL 16

/* Core BLOG functions - all require a valid logger parameter */

/**
 * blog_is_valid_kernel_addr - Check if address is in valid kernel address range
 * @addr: Address to check
 *
 * Returns true if address is in valid kernel address range
 */
bool blog_is_valid_kernel_addr(const void *addr)
{
	if (virt_addr_valid(addr)) {
		return true;
	}
	return false;
}
EXPORT_SYMBOL(blog_is_valid_kernel_addr);

/**
 * get_context_id - Get a unique context ID
 * @logger: Logger instance to use
 *
 * Acquires a unique ID for a TLS context using the logger's counter
 *
 * Returns a unique context ID
 */
static u64 get_context_id(struct blog_logger *logger)
{
	u64 id;
	spin_lock(&logger->ctx_id_lock);
	id = logger->next_ctx_id++;
	spin_unlock(&logger->ctx_id_lock);
	return id;
}

/**
 * validate_tls_ctx - Validate a TLS context
 * @ctx: Context to validate
 *
 * Returns true if context is valid, false otherwise
 */
static inline bool validate_tls_ctx(struct blog_tls_ctx *ctx)
{
	if (!ctx)
		return false;

#if BLOG_DEBUG_POISON
	if (ctx->debug_poison != BLOG_CTX_POISON) {
		pr_err("BUG: TLS context id=%llu (%llx) has invalid debug_poison value 0x%llx\n",
		       ctx->id, (unsigned long long)ctx,
		       (unsigned long long)ctx->debug_poison);
		return false;
	}
#endif

	if (atomic_read(&ctx->refcount) != 1) {
		pr_err("BUG: TLS context id=%llu (%llx) refcount %d, expected 1\n",
		       ctx->id, (unsigned long long)ctx,
		       atomic_read(&ctx->refcount));
		return false;
	}

	return true;
}

static inline struct blog_tls_ctx *get_tls_ctx(void)
{
	/* This function is now deprecated - use slot-based access instead */
	return NULL;
}

/**
 * add_context_to_global_list - Add a context to the global list
 * @ctx: The context to add to the global list
 *
 * Adds the context to the global list of contexts and updates stats
 */
static void add_context_to_logger_list(struct blog_logger *logger, struct blog_tls_ctx *ctx)
{
	if (!logger)
		return;
	
	spin_lock(&logger->lock);
	list_add(&ctx->list, &logger->contexts);
	logger->total_contexts_allocated++;
	spin_unlock(&logger->lock);
}

static void *alloc_tls_ctx(struct blog_logger *logger)
{
	struct blog_tls_ctx *ctx;
	
	if (!logger)
		return NULL;
	
	ctx = kmem_cache_alloc(logger->alloc_batch.magazine_cache,
			       GFP_KERNEL);
	if (!ctx) {
		pr_err("Failed to allocate TLS context from magazine cache\n");
		return NULL;
	}

	/* Initialize pagefrag */
	memset(&ctx->pf, 0, sizeof(ctx->pf));
	if (blog_pagefrag_init(&ctx->pf)) {
		pr_err("Failed to initialize pagefrag for TLS context\n");
		kmem_cache_free(logger->alloc_batch.magazine_cache, ctx);
		return NULL;
	}

	/* Assign unique ID and initialize debug poison */
#if BLOG_DEBUG_POISON
	ctx->debug_poison = BLOG_CTX_POISON;
#endif
	atomic_set(&ctx->refcount, 0);
	ctx->id = get_context_id(logger);
	ctx->logger = logger; /* Store parent logger reference */
	add_context_to_logger_list(logger, ctx);

	ctx->release = blog_tls_release_verbose;

	pr_debug(
		"[%d]blog: initialized refcount=0 for new context id=%llu (%llx)\n",
		smp_processor_id(), ctx->id, (unsigned long long)ctx);

	return ctx;
}

static inline struct blog_tls_ctx *get_new_ctx(struct blog_logger *logger)
{
	struct blog_tls_ctx *ctx;

	if (!logger)
		return NULL;

	/* Try to get context from batch first */
	ctx = blog_batch_get(&logger->alloc_batch);
	if (!ctx) {
		/* Create new context if batch is empty */
		ctx = alloc_tls_ctx(logger);
		if (!ctx)
			return NULL;
	}

#if BLOG_DEBUG_POISON
	/* Verify debug poison on context from batch or fresh allocation */
	if (ctx->debug_poison != BLOG_CTX_POISON) {
		pr_err("BUG: Context id=%llu from batch/alloc has invalid debug_poison 0x%llx\n",
		       ctx->id, (unsigned long long)ctx->debug_poison);
		BUG();
	}
#endif

	ctx->base_jiffies = jiffies;
	blog_pagefrag_reset(&ctx->pf);
	blog_logger_print_stats(logger);
	return ctx; /* Context returned with refcount = 0 */
}

/**
 * is_valid_active_ctx - Validate an active TLS context
 * @ctx: Context to validate
 * @context_description: String describing the context for error messages
 *
 * Returns true if context is valid (poison OK, refcount == 1), false otherwise
 */
static inline bool is_valid_active_ctx(struct blog_tls_ctx *ctx,
				       const char *context_description)
{
	if (!ctx) {
		pr_err("BUG: %s context is NULL.\n", context_description);
		return false;
	}

#if BLOG_DEBUG_POISON
	if (ctx->debug_poison != BLOG_CTX_POISON) {
		pr_err("BUG: %s context id=%llu (%llx) has invalid debug_poison value 0x%llx\n",
		       context_description, ctx->id, (unsigned long long)ctx,
		       (unsigned long long)ctx->debug_poison);
		return false;
	}
#endif

	if (atomic_read(&ctx->refcount) != 1) {
		pr_err("BUG: %s context id=%llu (%llx) refcount %d, expected 1\n",
		       context_description, ctx->id, (unsigned long long)ctx,
		       atomic_read(&ctx->refcount));
		return false;
	}
	return true;
}

/* Release function for TLS storage */
static void blog_tls_release(void *ptr)
{
	struct blog_tls_ctx *ctx = ptr;

	if (!ctx)
		return;

	if (atomic_dec_return(&ctx->refcount) != 0) {
		pr_err("BUG: TLS context id=%llu refcount %d after release\n",
		       ctx->id, atomic_read(&ctx->refcount));
		panic("blog: TLS context id=%llu refcount %d after release\n",
		      ctx->id, atomic_read(&ctx->refcount));
	}
	pr_debug("blog: decremented refcount=0 for context id=%llu\n", ctx->id);

	/* Add context to log batch */
	ctx->task = NULL;
	pr_debug("blog: releasing TLS context for pid %d [%s]\n", ctx->pid,
		 ctx->comm);
		 
	if (ctx->logger) {
		blog_batch_put(&ctx->logger->log_batch, ctx);

		/* If log_batch has too many full magazines, move one to alloc_batch */
		if (ctx->logger->log_batch.nr_full > BLOG_LOG_BATCH_MAX_FULL) {
			struct blog_magazine *mag;
			spin_lock(&ctx->logger->log_batch.full_lock);
			if (!list_empty(&ctx->logger->log_batch.full_magazines)) {
				mag = list_first_entry(
					&ctx->logger->log_batch.full_magazines,
					struct blog_magazine, list);
				list_del(&mag->list);
				ctx->logger->log_batch.nr_full--;
				spin_unlock(&ctx->logger->log_batch.full_lock);

				spin_lock(&ctx->logger->alloc_batch.full_lock);
				list_add(&mag->list,
					 &ctx->logger->alloc_batch.full_magazines);
				ctx->logger->alloc_batch.nr_full++;
				spin_unlock(&ctx->logger->alloc_batch.full_lock);
			} else {
				spin_unlock(&ctx->logger->log_batch.full_lock);
			}
		}
	} else {
		pr_err("BUG: TLS context id=%llu has no logger reference for batch release\n", ctx->id);
	}
}

static void blog_tls_release_verbose(void *ptr)
{
	struct blog_tls_ctx *ctx = (struct blog_tls_ctx *)ptr;

	if (!ctx) {
		pr_err("blog -- Callback : invalid TLS context pointer %d\n",
		       current->pid);
		return;
	}
#if BLOG_DEBUG_POISON
	if (ctx->debug_poison != BLOG_CTX_POISON) {
		pr_err("blog -- Callback : invalid TLS context id=%llu has invalid debug_poison value 0x%llx\n",
		       ctx->id, (unsigned long long)ctx->debug_poison);
		BUG();
	}
#endif
	if (atomic_read(&ctx->refcount) != 1) {
		pr_err("blog -- Callback : invalid TLS context refcount %d for pid %d [%s]\n",
		       atomic_read(&ctx->refcount), ctx->pid, ctx->comm);
		BUG();
	}
	blog_tls_release(ctx);
}

/**
 * blog_get_tls_ctx - Get or create TLS context for current task
 * @logger: Logger instance to use
 *
 * Returns pointer to TLS context or NULL on error
 */
struct blog_tls_ctx *blog_get_tls_ctx(struct blog_logger *logger)
{
	struct blog_tls_ctx *ctx = get_tls_ctx();

	/* Context already exists - handled by slot-based system */
	if (ctx)
		return ctx;

	/* Create new context */
	pr_debug("blog: creating new TLS context for pid %d [%s]\n",
		 current->pid, current->comm);

	ctx = get_new_ctx(logger);
	if (!ctx)
		return NULL;

	/* Set up TLS specific parts */
	/* Note: slot-based storage is handled by blog_module layer */
	ctx->task = current;
	ctx->pid = current->pid;
	strncpy(ctx->comm, current->comm, TASK_COMM_LEN);
	ctx->comm[TASK_COMM_LEN - 1] = '\0';

	/* Increment refcount from 0 to 1 */
	if (atomic_inc_return(&ctx->refcount) != 1) {
		pr_err("BUG: Failed to set refcount=1 for new TLS context id=%llu (was %d before inc)\n",
		       ctx->id, atomic_read(&ctx->refcount) - 1);
		BUG();
	}

	pr_debug(
		"blog: successfully created new TLS context id=%llu for pid %d [%s]\n",
		ctx->id, ctx->pid, ctx->comm);
	return ctx;
}
EXPORT_SYMBOL(blog_get_tls_ctx);

/**
 * blog_get_source_id - Get or create a source ID for the given location
 * @logger: Logger instance to use (NULL for global)
 * @file: Source file name
 * @func: Function name
 * @line: Line number
 * @fmt: Format string
 *
 * Returns a unique ID for this source location
 */
u32 blog_get_source_id(struct blog_logger *logger, const char *file,
		       const char *func, unsigned int line, const char *fmt)
{
	u32 id;

	if (!logger)
		return 0;

	id = atomic_inc_return(&logger->next_source_id);

	if (id >= BLOG_MAX_SOURCE_IDS) {
		/* If we run out of IDs, just use the first one */
		pr_warn("blog: source ID overflow, reusing ID 1\n");
		id = 1;
	}

	/* Store the source information in the logger's map */
	logger->source_map[id].file = file;
	logger->source_map[id].func = func;
	logger->source_map[id].line = line;
	logger->source_map[id].fmt = fmt;
	logger->source_map[id].warn_count = 0;
	return id;
}
EXPORT_SYMBOL(blog_get_source_id);

/**
 * blog_get_source_info - Get source info for a given ID
 * @id: Source ID
 *
 * Returns the source information for this ID
 */
struct blog_source_info *blog_get_source_info(struct blog_logger *logger, u32 id)
{
	if (!logger || unlikely(id == 0 || id >= BLOG_MAX_SOURCE_IDS))
		return NULL;
	return &logger->source_map[id];
}
EXPORT_SYMBOL(blog_get_source_info);

/**
 * blog_log - Log a message
 * @source_id: Source ID for this location
 * @client_id: Client ID for this message (module-specific)
 * @needed_size: Size needed for the message
 *
 * Returns a buffer to write the message into
 */
void *blog_log(struct blog_logger *logger, u32 source_id, u8 client_id, size_t needed_size)
{
    struct blog_tls_ctx *ctx;
    struct blog_log_entry *entry = NULL;
    int alloc;
    int retry_count = 0;

#if BLOG_TRACK_USAGE
	struct blog_source_info *source;
#endif
    /* Preserve payload length; compute rounded total allocation separately */
    size_t payload_len = needed_size;

    if (payload_len > BLOG_MAX_PAYLOAD) {
        pr_warn_once("blog_log: payload %zu exceeds max %u\n",
                     payload_len, BLOG_MAX_PAYLOAD);
        return NULL;
    }

    needed_size = round_up(payload_len + sizeof(struct blog_log_entry), 8);
#if BLOG_TRACK_USAGE
	/* Get source info to update stats */
	source = blog_get_source_info(logger, source_id);
	if (unlikely(source)) {
		if (in_serving_softirq()) {
			atomic_inc(&source->napi_usage);
			atomic_add(needed_size, &source->napi_bytes);
		} else {
			atomic_inc(&source->task_usage);
			atomic_add(needed_size, &source->task_bytes);
		}
	}
#endif

	while (entry == NULL) {
		ctx = blog_get_ctx(logger);
		if (!ctx) {
			pr_err("Failed to get TLS context\n");
			return NULL;
		}
		if (!blog_is_valid_kernel_addr(ctx)) {
			pr_err("blog_log: invalid TLS context address: %pK\n",
			       ctx);
			return NULL;
		}
		if (unlikely(retry_count)) {
			pr_debug(
				"[%d]Retrying allocation with ctx %llu (%s, pid %d) (retry %d, needed_size=%zu @ %d)\n",
				smp_processor_id(), ctx->id, ctx->comm,
				ctx->pid, retry_count, needed_size, source_id);
		}

		alloc = blog_pagefrag_alloc(&ctx->pf, needed_size);
		if (alloc == -ENOMEM) {
			pr_debug(
				"blog_log: allocation failed (needed %zu), resetting context\n",
				needed_size);
			blog_pagefrag_reset(&ctx->pf);
			retry_count++;
			if (retry_count > 3) {
				pr_err("blog_log: failed to allocate after 3 retries\n");
				return NULL;
			}
			continue;
		}

		entry = blog_pagefrag_get_ptr(&ctx->pf, alloc);
		if (!entry) {
			pr_err("blog_log: failed to get pointer from pagefrag\n");
			return NULL;
		}
		ctx->pf.last_entry = entry;
	}

#if BLOG_DEBUG_POISON
	entry->debug_poison = BLOG_LOG_ENTRY_POISON;
#endif
    entry->ts_delta = (u32)(jiffies - ctx->base_jiffies);
    entry->source_id = (u16)source_id;
    entry->len = (u8)payload_len;
    entry->client_id = client_id;
    entry->flags = 0;
    return entry->buffer;
}
EXPORT_SYMBOL(blog_log);

/**
 * blog_get_napi_ctx - Get NAPI context for current CPU
 */
struct blog_tls_ctx *blog_get_napi_ctx(struct blog_logger *logger)
{
    struct blog_tls_ctx **napi_ctx_ptr;

    if (!logger || !logger->napi_ctxs)
        return NULL;

    napi_ctx_ptr = per_cpu_ptr(logger->napi_ctxs, smp_processor_id());
    return napi_ctx_ptr ? *napi_ctx_ptr : NULL;
}
EXPORT_SYMBOL(blog_get_napi_ctx);

/**
 * blog_set_napi_ctx - Set NAPI context for current CPU
 */
void blog_set_napi_ctx(struct blog_logger *logger, struct blog_tls_ctx *ctx)
{
    struct blog_tls_ctx **napi_ctx_ptr;

    if (!logger || !logger->napi_ctxs)
        return;

    napi_ctx_ptr = per_cpu_ptr(logger->napi_ctxs, smp_processor_id());
    if (napi_ctx_ptr)
        *napi_ctx_ptr = ctx;
}
EXPORT_SYMBOL(blog_set_napi_ctx);

/**
 * blog_get_ctx - Get appropriate context based on context type
 */
struct blog_tls_ctx *blog_get_ctx(struct blog_logger *logger)
{
    if (in_serving_softirq()) {
        struct blog_tls_ctx *n = blog_get_napi_ctx(logger);
        if (n)
            return n;
        /* Fallback to TLS context if no NAPI context set */
    }
    return blog_get_tls_ctx(logger);
}
EXPORT_SYMBOL(blog_get_ctx);

/**
 * blog_log_trim - Trim the current context's pagefrag by n bytes
 */
int blog_log_trim(struct blog_logger *logger, unsigned int n)
{
	struct blog_tls_ctx *ctx = blog_get_ctx(logger);
	if (!ctx)
		return -EINVAL;

	blog_pagefrag_trim(&ctx->pf, n);
	return 0;
}
EXPORT_SYMBOL(blog_log_trim);

/**
 * blog_log_iter_init - Initialize the iterator for a specific pagefrag
 */
void blog_log_iter_init(struct blog_log_iter *iter, struct blog_pagefrag *pf)
{
	if (!iter || !pf)
		return;

	iter->pf = pf;
	iter->current_offset = 0;
	iter->end_offset = pf->head;
	iter->prev_offset = 0;
	iter->steps = 0;
}
EXPORT_SYMBOL(blog_log_iter_init);

/**
 * blog_log_iter_next - Get next log entry
 */
struct blog_log_entry *blog_log_iter_next(struct blog_log_iter *iter)
{
	struct blog_log_entry *entry;

	if (!iter || iter->current_offset >= iter->end_offset)
		return NULL;

	entry = blog_pagefrag_get_ptr(iter->pf, iter->current_offset);
	if (!entry)
		return NULL;

	iter->prev_offset = iter->current_offset;
	iter->current_offset +=
		round_up(sizeof(struct blog_log_entry) + entry->len, 8);
	iter->steps++;

	return entry;
}
EXPORT_SYMBOL(blog_log_iter_next);

/**
 * blog_des_entry - Deserialize entry with callback
 */
int blog_des_entry(struct blog_logger *logger, struct blog_log_entry *entry, 
		   char *output, size_t out_size, blog_client_des_fn client_cb)
{
	int len = 0;
	struct blog_source_info *source;

	if (!entry || !output)
		return -EINVAL;

	/* Let module handle client_id if callback provided */
	if (client_cb) {
		len = client_cb(output, out_size, entry->client_id);
		if (len < 0)
			return len;
	}

	/* Get source info */
	source = blog_get_source_info(logger, entry->source_id);
	if (!source) {
		len += snprintf(output + len, out_size - len,
				"[unknown source %u]", entry->source_id);
		return len;
	}

	/* Add source location */
	len += snprintf(output + len, out_size - len, "[%s:%s:%u] ",
			source->file, source->func, source->line);

	/* Deserialize the buffer content */
	len += blog_des_reconstruct(source->fmt, entry->buffer, 0, entry->len,
				    output + len, out_size - len);

	return len;
}
EXPORT_SYMBOL(blog_des_entry);

/* No global init/exit: consumers initialize per‑module contexts explicitly */

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Binary Logging Infrastructure (BLOG)");
