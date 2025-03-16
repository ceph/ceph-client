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
static struct ceph_san_logger g_logger;

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
void ceph_san_log(const char *file, unsigned int line, const char *fmt, ...)
{
    /* Format the message into local buffer first */
    char buf[256];
    struct ceph_san_tls_ctx *ctx;
    struct ceph_san_log_entry *entry;
    va_list args;
    u64 alloc;
    int len;

    ctx = ceph_san_get_tls_ctx();
    if (!ctx)
        return;

    va_start(args, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* Allocate entry from pagefrag */ //We need a spinlock here to protect printing
    alloc = cephsan_pagefrag_alloc(&ctx->pf, sizeof(*entry) + len + 1);
    while (!alloc) {
        entry = cephsan_pagefrag_get_ptr_from_tail(&ctx->pf);
        BUG_ON(entry->debug_poison != CEPH_SAN_LOG_ENTRY_POISON);
        BUG_ON(entry->len == 0);
        cephsan_pagefrag_free(&ctx->pf, entry->len);
        alloc = cephsan_pagefrag_alloc(&ctx->pf, sizeof(*entry) + len + 1);
    }
    entry = cephsan_pagefrag_get_ptr(&ctx->pf, alloc);

    /* Copy to entry buffer */
    memcpy(entry->buffer, buf, len + 1);
    entry->buffer[len] = '\0';

    /* Fill in entry details */
    entry->debug_poison = CEPH_SAN_LOG_ENTRY_POISON;
    entry->ts = jiffies;
    entry->line = line;
    entry->file = file;
    entry->len = len + sizeof(*entry) + 1;
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