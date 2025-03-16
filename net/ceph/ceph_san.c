#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/ceph/ceph_san.h>
#include <linux/mm.h>
#include <linux/module.h>

/* Use per-core TLS logger; no global list or lock needed */
DEFINE_PER_CPU(struct ceph_san_percore_logger, ceph_san_percore);
EXPORT_SYMBOL(ceph_san_percore);

DEFINE_PER_CPU(struct cephsan_pagefrag, ceph_san_pagefrag);

/* Global list of all TLS contexts and its protection lock */
LIST_HEAD(g_ceph_san_contexts);
DEFINE_SPINLOCK(g_ceph_san_contexts_lock);
EXPORT_SYMBOL(g_ceph_san_contexts);
EXPORT_SYMBOL(g_ceph_san_contexts_lock);

/* Memory caches for log entries */
struct kmem_cache *ceph_san_log_128_cache;
struct kmem_cache *ceph_san_log_256_cache;

struct kmem_cache *ceph_san_tls_logger_cache;

#define CEPH_SAN_SIG 0xDEADC0DE

/* Release function for TLS storage */
static void ceph_san_tls_release(void *ptr)
{
    struct tls_ceph_san_context *context = ptr;
    if (!context)
        return;

    if (context->sig != CEPH_SAN_SIG) {
        pr_err("sig is wrong %p %llx != %llx", context, context->sig, CEPH_SAN_SIG);
        return;
    }

    /* Remove from global list with lock protection */
    spin_lock(&g_ceph_san_contexts_lock);
    list_del(&context->list);
    spin_unlock(&g_ceph_san_contexts_lock);

    /* Free all log entries */
    int head_idx = context->logger.head_idx & (CEPH_SAN_MAX_LOGS - 1);
    int tail_idx = (head_idx + 1) & (CEPH_SAN_MAX_LOGS - 1);

    for (int i = tail_idx; (i & (CEPH_SAN_MAX_LOGS - 1)) != head_idx; i++) {
        struct ceph_san_log_entry_tls *entry = &context->logger.logs[i & (CEPH_SAN_MAX_LOGS - 1)];
        if (entry->buf) {
            if (entry->ts & 0x1)
                kmem_cache_free(ceph_san_log_256_cache, entry->buf);
            else
                kmem_cache_free(ceph_san_log_128_cache, entry->buf);
            entry->buf = NULL;
        }
    }

    kmem_cache_free(ceph_san_tls_logger_cache, context);
}

static struct tls_ceph_san_context *get_cephsan_context(void)
{
    struct tls_ceph_san_context *context;

    context = current->tls.state;
    if (context)
        return context;

    context = kmem_cache_alloc(ceph_san_tls_logger_cache, GFP_KERNEL);
    if (!context) {
        pr_err("Failed to allocate TLS logger for PID %d\n", current->pid);
        return NULL;
    }

    context->logger.pid = current->pid;
    memcpy(context->logger.comm, current->comm, TASK_COMM_LEN);

    /* Initialize list entry */
    INIT_LIST_HEAD(&context->list);
    context->sig = CEPH_SAN_SIG;

    current->tls.state = context;
    current->tls.release = ceph_san_tls_release;

    /* Add to global list with lock protection */
    spin_lock(&g_ceph_san_contexts_lock);
    list_add(&context->list, &g_ceph_san_contexts);
    spin_unlock(&g_ceph_san_contexts_lock);

    return context;
}

void log_cephsan_tls(char *buf)
{
    /* Use the task's TLS storage */
    int len = strlen(buf);
    struct tls_ceph_san_context *ctx;
    struct ceph_san_tls_logger *logger;
    char *new_buf;

    ctx = get_cephsan_context();
    if (!ctx)
        return;

    logger = &ctx->logger;

    /* Log the message */
    int head_idx = logger->head_idx + 1 & (CEPH_SAN_MAX_LOGS - 1);
    struct ceph_san_log_entry_tls *entry = &logger->logs[head_idx];

    /* Only free and reallocate if sizes differ */
    if (!entry->buf || (entry->ts & 0x1) != (len > LOG_BUF_SMALL)) {
        if (entry->buf) {
            if (entry->ts & 0x1)
                kmem_cache_free(ceph_san_log_256_cache, entry->buf);
            else
                kmem_cache_free(ceph_san_log_128_cache, entry->buf);
            entry->buf = NULL;
        }

        /* Allocate new buffer from appropriate cache */
        if (len <= LOG_BUF_SMALL) {
            new_buf = kmem_cache_alloc(ceph_san_log_128_cache, GFP_KERNEL);
            entry->ts = jiffies & ~0x1;
        } else {
            new_buf = kmem_cache_alloc(ceph_san_log_256_cache, GFP_KERNEL);
            entry->ts = jiffies | 0x1;
        }
    } else {
        /* Reuse existing buffer since size category hasn't changed */
        new_buf = entry->buf;
    }

    if (!new_buf)
        return;

    buf[len-1] = '\0';
    entry->buf = new_buf;
    memcpy(entry->buf, buf, len);

    logger->head_idx = head_idx;
}

static void log_cephsan_percore(char *buf)
{
    /* Use the per-core TLS logger */
    u64 buf_idx;
    int len = strlen(buf);
    struct ceph_san_percore_logger *pc = this_cpu_ptr(&ceph_san_percore);
    struct cephsan_pagefrag *pf = this_cpu_ptr(&ceph_san_pagefrag);

    int head_idx = pc->head_idx + 1 & (CEPH_SAN_MAX_LOGS - 1);
    int pre_len = pc->logs[head_idx].len;

    buf[len-1] = '\0';
    pc->logs[head_idx].pid = current->pid;
    pc->logs[head_idx].ts = jiffies;
    memcpy(pc->logs[head_idx].comm, current->comm, TASK_COMM_LEN);

    cephsan_pagefrag_free(pf, pre_len);
    pc->logs[head_idx].len = 0;

    buf_idx = cephsan_pagefrag_alloc(pf, len);
    if (buf_idx) {
        pc->head_idx = head_idx;
        pc->histogram.counters[(len >= 256) ? 31 : len >> 3]++;
        pc->logs[head_idx].len = len;
        pc->logs[head_idx].buf = cephsan_pagefrag_get_ptr(pf, buf_idx);
        memcpy(pc->logs[head_idx].buf, buf, len);
    }
}

void log_cephsan(char *buf)
{
    log_cephsan_percore(buf);
    log_cephsan_tls(buf);
}
EXPORT_SYMBOL(log_cephsan);

/* Cleanup function to free all TLS logger objects.
 * Call this at module exit to free allocated TLS loggers.
 */
void cephsan_cleanup(void)
{
    int cpu;
    struct ceph_san_percore_logger *pc;

    for_each_possible_cpu(cpu) {
        pc = per_cpu_ptr(&ceph_san_percore, cpu);
        if (pc->pages) {
            free_pages((unsigned long)pc->pages, get_order(CEPH_SAN_MAX_LOGS * sizeof(struct ceph_san_log_entry)));
            pc->pages = NULL;
        }
    }
#if 0
    /* Let the TLS contexts cleanup lazily */
    if (ceph_san_tls_logger_cache) {
        kmem_cache_destroy(ceph_san_tls_logger_cache);
        ceph_san_tls_logger_cache = NULL;
    }

    if (ceph_san_log_128_cache) {
        kmem_cache_destroy(ceph_san_log_128_cache);
        ceph_san_log_128_cache = NULL;
    }

    if (ceph_san_log_256_cache) {
        kmem_cache_destroy(ceph_san_log_256_cache);
        ceph_san_log_256_cache = NULL;
    }
#endif
}
EXPORT_SYMBOL(cephsan_cleanup);

/* Initialize the Ceph SAN logging infrastructure.
 * Call this at module init to set up the global list and lock.
 */
int cephsan_init(void)
{
    int cpu;
    struct ceph_san_percore_logger *pc;
    struct cephsan_pagefrag *pf;

    /* Initialize the global list */
    INIT_LIST_HEAD(&g_ceph_san_contexts);

    /* Create memory caches for log entries */
    ceph_san_log_128_cache = kmem_cache_create("ceph_san_log_128",
                                             LOG_BUF_SMALL,
                                             0, SLAB_HWCACHE_ALIGN,
                                             NULL);
    if (!ceph_san_log_128_cache)
        goto cleanup_128_cache;

    ceph_san_log_256_cache = kmem_cache_create("ceph_san_log_256",
                                             LOG_BUF_SIZE,
                                             0, SLAB_HWCACHE_ALIGN,
                                             NULL);
    if (!ceph_san_log_256_cache)
        goto cleanup_256_cache;

    ceph_san_tls_logger_cache = kmem_cache_create("ceph_san_tls_logger",
                                             sizeof(struct tls_ceph_san_context),
                                             0, SLAB_HWCACHE_ALIGN,
                                             NULL);
    if (!ceph_san_tls_logger_cache)
        goto cleanup_logger_cache;

    for_each_possible_cpu(cpu) {
        pc = per_cpu_ptr(&ceph_san_percore, cpu);
        pc->pages = alloc_pages(GFP_KERNEL, get_order(CEPH_SAN_MAX_LOGS * sizeof(struct ceph_san_log_entry)));
        if (!pc->pages) {
            pr_err("Failed to allocate TLS logs for CPU %d\n", cpu);
            goto cleanup;
        }
        pc->logs = (struct ceph_san_log_entry *)page_address(pc->pages);
    }

    for_each_possible_cpu(cpu) {
        pf = per_cpu_ptr(&ceph_san_pagefrag, cpu);
        cephsan_pagefrag_init(pf);
    }
    return 0;

cleanup:
    cephsan_cleanup();
    return -ENOMEM;

cleanup_logger_cache:
    kmem_cache_destroy(ceph_san_log_256_cache);
    ceph_san_log_256_cache = NULL;

cleanup_256_cache:
    kmem_cache_destroy(ceph_san_log_128_cache);
    ceph_san_log_128_cache = NULL;

cleanup_128_cache:
    return -ENOMEM;
}
EXPORT_SYMBOL(cephsan_init);

/**
 * cephsan_dump_all_contexts - Dump logs from all TLS contexts to a buffer
 * @buf: Buffer to write logs to
 * @size: Size of the buffer
 *
 * This function iterates through all TLS contexts in the global list and
 * dumps their logs to the provided buffer. It's useful for debugging and
 * crash analysis.
 *
 * Return: Number of bytes written to the buffer
 */
int cephsan_dump_all_contexts(char *buf, size_t size)
{
    struct tls_ceph_san_context *ctx;
    struct ceph_san_tls_logger *tls;
    struct ceph_san_log_entry_tls *entry;
    unsigned long flags;
    int len = 0;
    int count = 0;

    if (!buf || size == 0)
        return 0;

    len += snprintf(buf + len, size - len,
                   "=== Ceph SAN TLS logs from all contexts ===\n");

    spin_lock_irqsave(&g_ceph_san_contexts_lock, flags);

    list_for_each_entry(ctx, &g_ceph_san_contexts, list) {
        tls = &ctx->logger;
        count++;

        if (len >= size - 1)
            break;

        len += snprintf(buf + len, size - len,
                       "\n=== Context %d (PID %d, comm %s) ===\n",
                       count, tls->pid, tls->comm);
        int head_idx = tls->head_idx & (CEPH_SAN_MAX_LOGS - 1);
        int tail_idx = (head_idx + 1) & (CEPH_SAN_MAX_LOGS - 1);

        for (int i = tail_idx; (i & (CEPH_SAN_MAX_LOGS - 1)) != head_idx; i++) {
            struct timespec64 ts;
            entry = &tls->logs[i & (CEPH_SAN_MAX_LOGS - 1)];

            if (entry->ts == 0 || !entry->buf)
                continue;

            if (len >= size - 1)
                break;

            jiffies_to_timespec64(entry->ts, &ts);

            len += snprintf(buf + len, size - len,
                           "[%lld.%09ld] : %s\n",
                           (long long)ts.tv_sec,
                           ts.tv_nsec,
                           entry->buf ? entry->buf : "(null)");
        }
    }

    spin_unlock_irqrestore(&g_ceph_san_contexts_lock, flags);

    if (count == 0 && len < size - 1) {
        len += snprintf(buf + len, size - len, "No TLS contexts found.\n");
    } else if (len < size - 1) {
        len += snprintf(buf + len, size - len, "\nTotal contexts: %d\n", count);
    }

    return len;
}
EXPORT_SYMBOL(cephsan_dump_all_contexts);
