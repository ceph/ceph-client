#include <linux/slab.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/ceph/ceph_san_logger.h>

#define CEPH_SAN_LOG_BATCH_MAX_FULL 128
/* Global logger instance */
struct ceph_san_logger g_logger;
EXPORT_SYMBOL(g_logger);

static void *alloc_tls_ctx(void)
{
    struct ceph_san_tls_ctx *ctx;
    ctx = kmem_cache_alloc(g_logger.alloc_batch.magazine_cache, GFP_KERNEL);
    if (!ctx) {
        pr_err("Failed to allocate TLS context from magazine cache\n");
        return NULL;
    }

    /* Initialize pagefrag */
    memset(&ctx->pf, 0, sizeof(ctx->pf));
    if (cephsan_pagefrag_init(&ctx->pf)) {
        pr_err("Failed to initialize pagefrag for TLS context\n");
        kmem_cache_free(g_logger.alloc_batch.magazine_cache, ctx);
        return NULL;
    }
    return ctx;
}

static void free_tls_ctx(void *ptr)
{
    struct ceph_san_tls_ctx *ctx = ptr;
    cephsan_pagefrag_deinit(&ctx->pf);
    kmem_cache_free(g_logger.alloc_batch.magazine_cache, ctx);
}

/* Release function for TLS storage */
static void ceph_san_tls_release(void *ptr)
{
    struct ceph_san_tls_ctx *ctx = ptr;

    if (!ctx)
        return;

    /* Add context to log batch */
    ctx->task = NULL;
    ceph_san_batch_put(&g_logger.log_batch, ctx);

    /* If log_batch has too many full magazines, move one to alloc_batch */
    if (g_logger.log_batch.nr_full > CEPH_SAN_LOG_BATCH_MAX_FULL) {
        struct ceph_san_magazine *mag;
        spin_lock(&g_logger.log_batch.full_lock);
        if (!list_empty(&g_logger.log_batch.full_magazines)) {
            mag = list_first_entry(&g_logger.log_batch.full_magazines,
                                 struct ceph_san_magazine, list);
            list_del(&mag->list);
            g_logger.log_batch.nr_full--;
            spin_unlock(&g_logger.log_batch.full_lock);

            spin_lock(&g_logger.alloc_batch.full_lock);
            list_add(&mag->list, &g_logger.alloc_batch.full_magazines);
            g_logger.alloc_batch.nr_full++;
            spin_unlock(&g_logger.alloc_batch.full_lock);
        } else {
            spin_unlock(&g_logger.log_batch.full_lock);
        }
    }
    current->tls.state = NULL;
}

/**
 * ceph_san_get_tls_ctx - Get or create TLS context for current task
 *
 * Returns pointer to TLS context or NULL on error
 */
struct ceph_san_tls_ctx *ceph_san_get_tls_ctx(void)
{
    struct ceph_san_tls_ctx *ctx;

    ctx = current->tls.state;
    if (ctx)
        return ctx;

    /* Try to get context from batch first */
    ctx = ceph_san_batch_get(&g_logger.alloc_batch);
    if (!ctx) {
        /* Create new context if batch is empty */
        ctx = alloc_tls_ctx();
        if (!ctx)
            return NULL;
        /* Add to global list */
        spin_lock(&g_logger.lock);
        list_add(&ctx->list, &g_logger.contexts);
        spin_unlock(&g_logger.lock);
    }
    cephsan_pagefrag_reset(&ctx->pf);
    /* Set up TLS */
    current->tls.state = ctx;
    current->tls.release = ceph_san_tls_release;
    task_state_to_char(current);
    ctx->task = current;
    ctx->pid = current->pid;
    strncpy(ctx->comm, current->comm, sizeof(ctx->comm));
    return ctx;
}
EXPORT_SYMBOL(ceph_san_get_tls_ctx);

/**
 * ceph_san_log - Log a message
 * @file: Source file name
 * @line: Line number
 * @fmt: Format string
 *
 * Logs a message to the current TLS context's log buffer
 */
void ceph_san_log(const char *file, const char *func, unsigned int line, const char *fmt, ...)
{
    /* Format the message into local buffer first */
    char buf[256];
    struct ceph_san_tls_ctx *ctx;
    struct ceph_san_log_entry *entry;
    va_list args;
    u64 alloc;
    int len, needed_size;

    ctx = ceph_san_get_tls_ctx();
    if (!ctx) {
        pr_err("Failed to get TLS context\n");
        return;
    }

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    needed_size = sizeof(*entry) + len + 1;
    /* Allocate entry from pagefrag - We need a spinlock here to protect access iterators */
    spin_lock(&ctx->pf.lock);
    alloc = cephsan_pagefrag_alloc(&ctx->pf, needed_size);
    int loop_count = 0;
    while (!alloc) {
        entry = cephsan_pagefrag_get_ptr_from_tail(&ctx->pf);
        if (loop_count++ >= 32) {
            pr_err("ceph_san_log: pagefrag stats - head: %u, tail: %u, size: %u, free: %d\n",
                  ctx->pf.head, ctx->pf.tail,
                  CEPHSAN_PAGEFRAG_SIZE,
                  (ctx->pf.tail > ctx->pf.head) ?
                      ctx->pf.tail - ctx->pf.head :
                      CEPHSAN_PAGEFRAG_SIZE - (ctx->pf.head - ctx->pf.tail));

            panic("ceph_san_log: failed to allocate entry after 8 retries");
        }
        if (entry->debug_poison != CEPH_SAN_LOG_ENTRY_POISON || entry->len == 0) {
            pr_err("ceph_san_log: pagefrag corruption detected\n");
            pr_err("  head: %u, tail: %u, size: %u\n",
                  ctx->pf.head, ctx->pf.tail, CEPHSAN_PAGEFRAG_SIZE);
            pr_err("  active_elements: %u, alloc_count: %u\n",
                  ctx->pf.active_elements, ctx->pf.alloc_count);
            pr_err("  entry poison: %llx, len: %u\n",
                  entry->debug_poison, entry->len);
            BUG();
        }
        cephsan_pagefrag_free(&ctx->pf, entry->len);
        alloc = cephsan_pagefrag_alloc(&ctx->pf, needed_size);
    }
    entry = cephsan_pagefrag_get_ptr(&ctx->pf, alloc);

    /* Fill in entry details */
    entry->debug_poison = CEPH_SAN_LOG_ENTRY_POISON;
    entry->ts = jiffies;
    entry->line = line;
    entry->file = file;
    entry->func = func;
    if (unlikely(cephsan_pagefrag_is_wraparound(alloc))) {
        entry->buffer = cephsan_pagefrag_get_ptr(&ctx->pf, 0);
    } else {
        entry->buffer = (char *)(entry + 1);
    }
    entry->len = cephsan_pagefrag_get_alloc_size(alloc);
    spin_unlock(&ctx->pf.lock);

    /* Copy to entry buffer */
    memcpy(entry->buffer, buf, len + 1);
    entry->buffer[len] = '\0';
}
EXPORT_SYMBOL(ceph_san_log);

/**
 * ceph_san_logger_init - Initialize the logging system
 *
 * Returns 0 on success, negative error code on failure
 */
int ceph_san_logger_init(void)
{
    int ret;

    /* Initialize global state */
    INIT_LIST_HEAD(&g_logger.contexts);
    spin_lock_init(&g_logger.lock);

    /* Initialize allocation batch */
    ret = ceph_san_batch_init(&g_logger.alloc_batch);
    if (ret)
        return ret;

    /* Initialize log batch */
    ret = ceph_san_batch_init(&g_logger.log_batch);
    if (ret)
        goto cleanup_alloc;

    return 0;

cleanup_alloc:
    ceph_san_batch_cleanup(&g_logger.alloc_batch);
    return ret;
}
EXPORT_SYMBOL(ceph_san_logger_init);

/**
 * ceph_san_logger_cleanup - Clean up the logging system
 */
void ceph_san_logger_cleanup(void)
{
    struct ceph_san_tls_ctx *ctx, *tmp;

    /* Clean up all TLS contexts */
    spin_lock(&g_logger.lock);
    list_for_each_entry_safe(ctx, tmp, &g_logger.contexts, list) {
        list_del(&ctx->list);
        free_tls_ctx(ctx);
    }
    spin_unlock(&g_logger.lock);

    /* Clean up batches */
    ceph_san_batch_cleanup(&g_logger.alloc_batch);
    ceph_san_batch_cleanup(&g_logger.log_batch);
}
EXPORT_SYMBOL(ceph_san_logger_cleanup);

/**
 * ceph_san_log_iter_init - Initialize the log entry iterator for a specific pagefrag
 * @iter: Iterator structure to initialize
 * @pf: Pagefrag to iterate over
 */
void ceph_san_log_iter_init(struct ceph_san_log_iter *iter, struct cephsan_pagefrag *pf)
{
    /* Initialize iterator state */
    iter->pf = pf;
    iter->current_offset = pf->tail;
    iter->end_offset = pf->head;
    iter->prev_offset = pf->tail;
}
EXPORT_SYMBOL(ceph_san_log_iter_init);

/**
 * ceph_san_log_iter_next - Get the next log entry from the iterator
 * @iter: Iterator structure
 *
 * Returns the next log entry or NULL if no more entries are available.
 */
struct ceph_san_log_entry *ceph_san_log_iter_next(struct ceph_san_log_iter *iter)
{
    struct ceph_san_log_entry *entry;

    if (!iter->pf || iter->current_offset == iter->end_offset)
        return NULL;

    /* Get current entry */
    entry = cephsan_pagefrag_get_ptr(iter->pf, iter->current_offset);
    /* Verify entry is valid */
    if (!entry || entry->debug_poison != CEPH_SAN_LOG_ENTRY_POISON || entry->len == 0) {
        //This maybe legitimate the head doesnt have to be aligned to the tail
        //if the last free was bigger than need alloc size
       return NULL;
    }

    /* Store current offset before moving to next */
    iter->prev_offset = iter->current_offset;
    /* Move to next entry */
    iter->current_offset += entry->len & CEPHSAN_PAGEFRAG_MASK;

    return entry;
}
EXPORT_SYMBOL(ceph_san_log_iter_next);