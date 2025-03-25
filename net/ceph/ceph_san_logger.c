#include <linux/slab.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/ceph/ceph_san_logger.h>

#define CEPH_SAN_LOG_BATCH_MAX_FULL 128
/* Global logger instance */
struct ceph_san_logger g_logger;
EXPORT_SYMBOL(g_logger);

/* Registration table */
struct ceph_san_log_registration g_registrations[CEPH_SAN_LOG_MAX_REGISTRATIONS];
EXPORT_SYMBOL(g_registrations);

static unsigned int g_next_reg_id;
static DEFINE_SPINLOCK(g_reg_lock);

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
 * ceph_san_log - Log a message with file/func/line registration
 * @file: Source file name (static string)
 * @func: Function name (static string)
 * @line: Line number
 * @fmt:  Format string (static string)
 *
 * Registers the location on first call and reuses registration ID on subsequent calls.
 * The static global ID is stored in the first word of the format string buffer.
 */
void ceph_san_log(const char *file, const char *func, unsigned int line,
              const char *fmt, ...)
{
    static unsigned int *p_reg_id = NULL;
    unsigned int reg_id = 0;
    va_list args;

    /* Check if we've registered this location before */
    if (likely(p_reg_id)) {
        reg_id = *p_reg_id;
    } else {
        /* First call - register this location */
        reg_id = ceph_san_log_register(file, func, line, fmt);
        if (!reg_id) {
            /* Registration failed */
            pr_err("ceph_san_log: registration failed for %s:%s:%d\n",
                  file, func, line);
            return;
        }
        
        /* Store registration ID in the format string's first word */
        p_reg_id = (unsigned int *)fmt;
        *p_reg_id = reg_id;
    }
    
    /* Call the ID-based logger with the same arguments */
    va_start(args, fmt);
    ceph_san_log_with_id_v(reg_id, fmt, args);
    va_end(args);
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
    g_next_reg_id = 1;  /* Start IDs at 1, 0 is invalid */

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
    iter->steps = 0;
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

    iter->steps++;
    /* Store current offset before moving to next */
    iter->prev_offset = iter->current_offset;
    /* Move to next entry */
    iter->current_offset = (iter->current_offset + entry->len) & CEPHSAN_PAGEFRAG_MASK;

    if (iter->steps > iter->pf->active_elements || iter->current_offset == iter->prev_offset) {
        pr_err("ceph_san_log_iter_next: steps: %llu, active_elements: %u, entry_len: %u\n",
               iter->steps, iter->pf->active_elements, entry->len);
        pr_err("ceph_san_log_iter_next: pagefrag details:\n"
               "  head: %u, tail: %u, current: %llu\n"
               "  prev_offset: %llu, end_offset: %llu\n"
               "  active_elements: %d, alloc_count: %u\n"
               "  wrap_to_end: %u, wrap_around: %u\n",
               iter->pf->head, iter->pf->tail, iter->current_offset,
               iter->prev_offset, iter->end_offset,
               iter->pf->active_elements, iter->pf->alloc_count,
               iter->pf->wrap_to_end, iter->pf->wrap_around);

        BUG();
    }


    return entry;
}
EXPORT_SYMBOL(ceph_san_log_iter_next);

/**
 * ceph_san_log_register - Register a logging location
 * @file: Source file name (static string)
 * @func: Function name (static string)
 * @line: Line number
 * @fmt: Format string (static string)
 *
 * Registers a logging location to avoid storing the same information in each log entry.
 * Returns a registration ID or 0 on failure.
 */
unsigned int ceph_san_log_register(const char *file, const char *func,
                           unsigned int line, const char *fmt)
{
    unsigned int reg_id;
    unsigned int params_size;

    if (!file || !func || !fmt)
        return 0;

    spin_lock_bh(&g_reg_lock);

    /* Check if this is a duplicate registration */
    for (reg_id = 1; reg_id < g_next_reg_id; reg_id++) {
        if (g_registrations[reg_id].file == file &&
            g_registrations[reg_id].func == func &&
            g_registrations[reg_id].line == line &&
            g_registrations[reg_id].fmt == fmt) {
            spin_unlock_bh(&g_reg_lock);
            return reg_id;
        }
    }

    /* Check if we have space for a new registration */
    if (g_next_reg_id >= CEPH_SAN_LOG_MAX_REGISTRATIONS) {
        spin_unlock_bh(&g_reg_lock);
        pr_err("Too many log registrations\n");
        return 0;
    }

    /* Calculate the size of parameters when compacted */
    params_size = strlen(file) + 1 + strlen(func) + 1 + sizeof(unsigned int) + strlen(fmt) + 1;

    /* Create a new registration */
    reg_id = g_next_reg_id++;
    g_registrations[reg_id].file = file;
    g_registrations[reg_id].func = func;
    g_registrations[reg_id].line = line;
    g_registrations[reg_id].fmt = fmt;
    g_registrations[reg_id].id = reg_id;
    g_registrations[reg_id].params_size = params_size;

    spin_unlock_bh(&g_reg_lock);
    return reg_id;
}
EXPORT_SYMBOL(ceph_san_log_register);

/**
 * ceph_san_log_with_id_v - Log a message using registration ID with va_list
 * @reg_id: Registration ID
 * @fmt: Format string
 * @args: Variable argument list
 *
 * Logs a message using a pre-registered ID. The parameters are compacted
 * and stored efficiently.
 */
void ceph_san_log_with_id_v(unsigned int reg_id, const char *fmt, va_list args)
{
    char buf[256];
    struct ceph_san_tls_ctx *ctx;
    struct ceph_san_log_entry *entry;
    struct ceph_san_log_registration *reg;
    u64 alloc;
    int len, needed_size;

    /* Validate registration ID */
    if (!reg_id || reg_id >= g_next_reg_id) {
        pr_err("ceph_san_log: invalid registration ID %u\n", reg_id);
        return;
    }

    /* Get registration info */
    reg = &g_registrations[reg_id];
    if (reg->fmt != fmt) {
        pr_err("ceph_san_log: format string mismatch for ID %u\n", reg_id);
        return;
    }

    /* Get TLS context */
    ctx = ceph_san_get_tls_ctx();
    if (!ctx) {
        pr_err("Failed to get TLS context\n");
        return;
    }

    /* Format message with arguments */
    len = vsnprintf(buf, sizeof(buf), fmt, args);

    /* Allocate log entry with compacted parameters */
    needed_size = sizeof(*entry) + len + 1;
    
    spin_lock_bh(&ctx->pf.lock);
    alloc = cephsan_pagefrag_alloc(&ctx->pf, needed_size);
    
    /* Handle allocation failures by freeing older entries */
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

            panic("ceph_san_log: failed to allocate entry after 32 retries");
        }
        
        /* Check for corruption */
        if (entry->debug_poison != CEPH_SAN_LOG_ENTRY_POISON || entry->len == 0) {
            struct ceph_san_log_registration *reg = &g_registrations[entry->reg_id];
            pr_err("ceph_san_log: pagefrag corruption detected\n");
            pr_err("  head: %u, tail: %u, size: %u\n",
                  ctx->pf.head, ctx->pf.tail, CEPHSAN_PAGEFRAG_SIZE);
            pr_err("  active_elements: %u, alloc_count: %u\n",
                  ctx->pf.active_elements, ctx->pf.alloc_count);
            pr_err("  entry poison: %llx, len: %u\n",
                  entry->debug_poison, entry->len);
            pr_err("  wrap_to_end: %u, wrap_around: %u\n",
                  ctx->pf.wrap_to_end, ctx->pf.wrap_around);
            pr_err("  location: %s:%s:%u\n",
                  reg->file, reg->func, reg->line);
            BUG();
        }
        
        /* Free the entry and try again */
        cephsan_pagefrag_free(&ctx->pf, entry->len);
        alloc = cephsan_pagefrag_alloc(&ctx->pf, needed_size);
    }
    
    /* Get pointer to the allocated entry */
    entry = cephsan_pagefrag_get_ptr(&ctx->pf, alloc);

    /* Fill in entry details */
    entry->debug_poison = CEPH_SAN_LOG_ENTRY_POISON;
    entry->ts = jiffies;
    entry->reg_id = reg_id;
    
    /* Handle buffer wraparound */
    if (unlikely(cephsan_pagefrag_is_wraparound(alloc))) {
        entry->buffer = cephsan_pagefrag_get_ptr(&ctx->pf, 0);
    } else {
        entry->buffer = (char *)(entry + 1);
    }
    
    entry->len = len;
    spin_unlock_bh(&ctx->pf.lock);

    /* Copy the formatted message to the buffer */
    memcpy(entry->buffer, buf, len + 1);
    entry->buffer[len] = '\0';
}

/**
 * ceph_san_log_with_id - Log a message using registration ID
 * @reg_id: Registration ID
 * @fmt: Format string
 *
 * Logs a message using a pre-registered ID. The parameters are compacted
 * and stored efficiently.
 */
void ceph_san_log_with_id(unsigned int reg_id, const char *fmt, ...)
{
    va_list args;
    
    va_start(args, fmt);
    ceph_san_log_with_id_v(reg_id, fmt, args);
    va_end(args);
}
EXPORT_SYMBOL(ceph_san_log_with_id);