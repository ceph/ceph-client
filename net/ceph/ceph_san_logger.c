/* Standard kernel includes */
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

/* Ceph SAN includes */
#include <linux/ceph/ceph_san_logger.h>
#include <linux/ceph/ceph_san_batch.h>
#include <linux/ceph/ceph_san_pagefrag.h>
#include <linux/ceph/ceph_san_ser.h>
#include <linux/ceph/ceph_san_des.h>

static void ceph_san_tls_release_verbose(void *ptr);
#define NULL_STR "(NULL)"
/**
 * is_valid_kernel_addr - Check if address is in valid kernel address range
 * @addr: Address to check
 *
 * Returns true if address is in valid kernel address range
 */
bool is_valid_kernel_addr(const void *addr)
{
    if (virt_addr_valid(addr)) {
        return true;
    }
    return false;
}
EXPORT_SYMBOL(is_valid_kernel_addr);

#define CEPH_SAN_LOG_BATCH_MAX_FULL 16
/* Global logger instance */
struct ceph_san_logger g_logger;
EXPORT_SYMBOL(g_logger);

/**
 * get_context_id - Get a unique context ID
 *
 * Acquires a unique ID for a TLS context using the global counter
 *
 * Returns a unique context ID
 */
static u64 get_context_id(void)
{
    u64 id;
    spin_lock(&g_logger.ctx_id_lock);
    id = g_logger.next_ctx_id++;
    spin_unlock(&g_logger.ctx_id_lock);
    return id;
}

/**
 * validate_tls_ctx - Validate a TLS context
 * @ctx: Context to validate
 *
 * Returns true if context is valid, false otherwise
 */
static inline bool validate_tls_ctx(struct ceph_san_tls_ctx *ctx)
{
    if (!ctx)
        return false;

    if (ctx->debug_poison != CEPH_SAN_CTX_POISON) {
        pr_err("BUG: TLS context id=%llu (%llx) has invalid debug_poison value 0x%llx\n",
               ctx->id, (unsigned long long)ctx, (unsigned long long)ctx->debug_poison);
        return false;
    }

    if (atomic_read(&ctx->refcount) != 1) {
        pr_err("BUG: TLS context id=%llu (%llx) refcount %d, expected 1\n",
               ctx->id, (unsigned long long)ctx, atomic_read(&ctx->refcount));
        return false;
    }

    return true;
}

static inline struct ceph_san_tls_ctx *get_tls_ctx(void)
{
    struct ceph_san_tls_ctx *ctx = current->tls_ctx;
    if (likely(ctx)) {
        ctx = container_of((void *)ctx, struct ceph_san_tls_ctx, release);
    }
    return ctx;
}

/**
 * add_context_to_global_list - Add a context to the global list
 * @ctx: The context to add to the global list
 *
 * Adds the context to the global list of contexts and updates stats
 */
static void add_context_to_global_list(struct ceph_san_tls_ctx *ctx)
{
    spin_lock(&g_logger.lock);
    list_add(&ctx->list, &g_logger.contexts);
    g_logger.total_contexts_allocated++;
    spin_unlock(&g_logger.lock);
}

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

    /* Assign unique ID and initialize debug poison */
    ctx->debug_poison = CEPH_SAN_CTX_POISON;
    atomic_set(&ctx->refcount, 0);
    ctx->id = get_context_id();
    add_context_to_global_list(ctx);

    ctx->release = ceph_san_tls_release_verbose;

    pr_debug("[%d]ceph_san_logger: initialized refcount=0 for new context id=%llu (%llx)\n",
            smp_processor_id(), ctx->id, (unsigned long long)ctx);

    return ctx;
}

static inline struct ceph_san_tls_ctx *get_new_ctx(void)
{
    struct ceph_san_tls_ctx *ctx;

    /* Try to get context from batch first */
    ctx = ceph_san_batch_get(&g_logger.alloc_batch);
    if (!ctx) {
        /* Create new context if batch is empty */
        ctx = alloc_tls_ctx(); /* alloc_tls_ctx sets poison, id, refcount=0 */
        if (!ctx)
            return NULL; /* alloc_tls_ctx already prints error if kmem_cache_alloc fails */
    }

    /* Verify debug poison on context from batch or fresh allocation */
    if (ctx->debug_poison != CEPH_SAN_CTX_POISON) {
        pr_err("BUG: Context id=%llu from batch/alloc has invalid debug_poison 0x%llx\n",
               ctx->id, (unsigned long long)ctx->debug_poison);
        BUG();
    }

    ctx->base_jiffies = jiffies;
    cephsan_pagefrag_reset(&ctx->pf);
    ceph_san_logger_print_stats(&g_logger); /* Moved from original new context block */
    return ctx; /* Context returned with refcount = 0 */
}

/**
 * is_valid_active_ctx - Validate an active TLS context
 * @ctx: Context to validate
 * @context_description: String describing the context for error messages
 *
 * Returns true if context is valid (poison OK, refcount == 1), false otherwise
 */
static inline bool is_valid_active_ctx(struct ceph_san_tls_ctx *ctx, const char *context_description)
{
    if (!ctx) {
        pr_err("BUG: %s context is NULL.\n", context_description);
        return false; /* Should not happen if called after a NULL check */
    }

    if (ctx->debug_poison != CEPH_SAN_CTX_POISON) {
        pr_err("BUG: %s context id=%llu (%llx) has invalid debug_poison value 0x%llx\n",
               context_description, ctx->id, (unsigned long long)ctx,
               (unsigned long long)ctx->debug_poison);
        return false;
    }

    if (atomic_read(&ctx->refcount) != 1) {
        pr_err("BUG: %s context id=%llu (%llx) refcount %d, expected 1\n",
               context_description, ctx->id, (unsigned long long)ctx,
               atomic_read(&ctx->refcount));
        return false;
    }
    return true;
}

static void free_tls_ctx(void *ptr)
{
    struct ceph_san_tls_ctx *ctx = ptr;

    if (!ctx) {
        pr_err("BUG: Trying to free NULL TLS context\n");
        return;
    }

    if (ctx->debug_poison != CEPH_SAN_CTX_POISON) {
        pr_err("BUG: TLS context id=%llu has invalid debug_poison value 0x%llx\n",
               ctx->id, (unsigned long long)ctx->debug_poison);
        return;
    }

    if (atomic_read(&ctx->refcount) != 0) {
        pr_err("BUG: Freeing TLS context id=%llu with non-zero refcount %d\n",
               ctx->id, atomic_read(&ctx->refcount));
        return;
    }

    pr_err("ceph_san_logger: freeing context id=%llu\n", ctx->id);
    cephsan_pagefrag_deinit(&ctx->pf);
    kmem_cache_free(g_logger.alloc_batch.magazine_cache, ctx);
}

/* Release function for TLS storage */
static void ceph_san_tls_release(void *ptr)
{
    struct ceph_san_tls_ctx *ctx = ptr;

    if (!ctx)
        return;

    if (atomic_dec_return(&ctx->refcount) != 0) {
        pr_err("BUG: TLS context id=%llu refcount %d after release\n",
               ctx->id, atomic_read(&ctx->refcount));
        panic("ceph_san_logger: TLS context id=%llu refcount %d after release\n", ctx->id, atomic_read(&ctx->refcount));
    }
    pr_debug("ceph_san_logger: decremented refcount=0 for context id=%llu\n", ctx->id);

    /* Add context to log batch */
    ctx->task = NULL;
    pr_debug("ceph_san_logger: releasing TLS context for pid %d [%s]\n",
             ctx->pid, ctx->comm);
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
}

static void ceph_san_tls_release_verbose(void *ptr)
{
    struct ceph_san_tls_ctx *ctx = container_of(ptr, struct ceph_san_tls_ctx, release);
    if (!ctx) {
        pr_err("ceph_san_logger -- Callback : invalid TLS context pointer %d\n", current->pid);
        return;
    }
    if (ctx->debug_poison != CEPH_SAN_CTX_POISON) {
        pr_err("ceph_san_logger -- Callback : invalid TLS context id=%llu has invalid debug_poison value 0x%llx\n",
               ctx->id, (unsigned long long)ctx->debug_poison);
        BUG();
    }
    if (atomic_read(&ctx->refcount) != 1) {
        pr_err("ceph_san_logger -- Callback : invalid TLS context refcount %d for pid %d [%s]\n",
               atomic_read(&ctx->refcount), ctx->pid, ctx->comm);
        BUG();
    }
    ceph_san_tls_release(ctx);
}
/**
 * ceph_san_get_tls_ctx - Get or create TLS context for current task
 *
 * Returns pointer to TLS context or NULL on error
 */
struct ceph_san_tls_ctx *ceph_san_get_tls_ctx(void)
{
    struct ceph_san_tls_ctx *ctx = get_tls_ctx(); /* Inline helper, gets container_of */

    if (ctx) {
        if (!is_valid_active_ctx(ctx, "Existing TLS")) {
            current->tls_ctx = NULL; /* Invalidate bad pointer */
            BUG();
        }
        return ctx;
    }

    /* Create new context */
    pr_debug("ceph_san_logger: creating new TLS context for pid %d [%s]\n",
             current->pid, current->comm);

    ctx = get_new_ctx(); /* Get base context with refcount 0 */
    if (!ctx)
        return NULL;

    /* Set up TLS specific parts */
    current->tls_ctx = (void *)&ctx->release;
    ctx->task = current;
    ctx->pid = current->pid;
    strncpy(ctx->comm, current->comm, TASK_COMM_LEN);
    ctx->comm[TASK_COMM_LEN - 1] = '\0'; /* Ensure null termination */

    /* Increment refcount from 0 to 1 */
    if (atomic_inc_return(&ctx->refcount) != 1) {
        pr_err("BUG: Failed to set refcount=1 for new TLS context id=%llu (was %d before inc)\n",
                ctx->id, atomic_read(&ctx->refcount) - 1);
        current->tls_ctx = NULL; /* Don't leave partially set up context */
        BUG();
    }

    pr_debug("ceph_san_logger: successfully created new TLS context id=%llu for pid %d [%s]\n",
           ctx->id, ctx->pid, ctx->comm);
    return ctx;
}
EXPORT_SYMBOL(ceph_san_get_tls_ctx);

/**
 * ceph_san_get_source_id - Get or create a source ID for the given location
 * @file: Source file name
 * @func: Function name
 * @line: Line number
 * @fmt: Format string
 *
 * Returns a unique ID for this source location
 */
u32 ceph_san_get_source_id(const char *file, const char *func, unsigned int line, const char *fmt)
{
    u32 id = atomic_inc_return(&g_logger.next_source_id);

    if (id >= CEPH_SAN_MAX_SOURCE_IDS) {
        /* If we run out of IDs, just use the first one */
        pr_warn("ceph_san_logger: source ID overflow, reusing ID 1\n");
        id = 1;
    }

    /* Store the source information in the global map */
    g_logger.source_map[id].file = file;
    g_logger.source_map[id].func = func;
    g_logger.source_map[id].line = line;
    g_logger.source_map[id].fmt = fmt;
    g_logger.source_map[id].warn_count = 0;
    return id;
}
EXPORT_SYMBOL(ceph_san_get_source_id);

/**
 * ceph_san_get_source_info - Get source info for a given ID
 * @id: Source ID
 *
 * Returns the source information for this ID
 */
struct ceph_san_source_info *ceph_san_get_source_info(u32 id)
{
    if (unlikely(id == 0 || id >= CEPH_SAN_MAX_SOURCE_IDS))
        return NULL;
    return &g_logger.source_map[id];
}
EXPORT_SYMBOL(ceph_san_get_source_info);

/**
 * ceph_san_check_client_id - Check if a client ID matches the given fsid:global_id pair
 * @id: Client ID to check
 * @fsid: Client FSID to compare
 * @global_id: Client global ID to compare
 *
 * Returns the actual ID of the pair. If the given ID doesn't match, scans for
 * existing matches or allocates a new ID if no match is found.
 */
u32 ceph_san_check_client_id(u32 id, const char *fsid, u64 global_id)
{
    u32 found_id = 0;
    char fsid_readable[64];
    struct ceph_san_client_id *entry;
    u32 max_id;

    /* First check if the given ID matches */
    if (id != 0 && id < CEPH_SAN_MAX_CLIENT_IDS) {
        entry = &g_logger.client_map[id];
        if (memcmp(entry->fsid, fsid, sizeof(entry->fsid)) == 0 &&
            entry->global_id == global_id) {
            found_id = id;
            goto out_fast;
        }
    }

    spin_lock(&g_logger.client_lock);
    max_id = g_logger.next_client_id;

    /* Scan for existing match */
    for (id = 1; id < max_id && id < CEPH_SAN_MAX_CLIENT_IDS; id++) {
        entry = &g_logger.client_map[id];
        if (memcmp(entry->fsid, fsid, sizeof(entry->fsid)) == 0 &&
            entry->global_id == global_id) {
            found_id = id;
            goto out;
        }
    }

    /* No match found, allocate new ID */
    found_id = ++g_logger.next_client_id;
    if (found_id >= CEPH_SAN_MAX_CLIENT_IDS) {
        /* If we run out of IDs, just use the first one */
        pr_warn("ceph_san_logger: client ID overflow, reusing ID 1\n");
        found_id = 1;
    }
    snprintf(fsid_readable, sizeof(fsid_readable),
             "%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x-%02x%02x%02x%02x",
             fsid[0], fsid[1], fsid[2], fsid[3], fsid[4], fsid[5], fsid[6], fsid[7],
             fsid[8], fsid[9], fsid[10], fsid[11], fsid[12], fsid[13], fsid[14], fsid[15]);
    pr_info("ceph_san_logger: allocating new client ID %u (next=%u) for fsid=%s global_id=%llu\n",
            found_id, g_logger.next_client_id, fsid_readable, global_id);
    entry = &g_logger.client_map[found_id];
    memcpy(entry->fsid, fsid, sizeof(entry->fsid));
    entry->global_id = global_id;

out:
    spin_unlock(&g_logger.client_lock);
out_fast:
    return found_id;
}
EXPORT_SYMBOL(ceph_san_check_client_id);

/**
 * ceph_san_get_client_info - Get client info for a given ID
 * @id: Client ID
 *
 * Returns the client information for this ID
 */
const struct ceph_san_client_id *ceph_san_get_client_info(u32 id)
{
    if (id == 0 || id >= CEPH_SAN_MAX_CLIENT_IDS)
        return NULL;
    return &g_logger.client_map[id];
}
EXPORT_SYMBOL(ceph_san_get_client_info);

/**
 * ceph_san_log - Log a message
 * @source_id: Source ID for this location
 * @client_id: Client ID for this message
 * @needed_size: Size needed for the message
 *
 * Returns a buffer to write the message into
 */
void* ceph_san_log(u32 source_id, u32 client_id, size_t needed_size)
{
    struct ceph_san_tls_ctx *ctx;
    struct ceph_san_log_entry *entry = NULL;
    u64 alloc;
    int retry_count = 0;

#if CEPH_SAN_TRACK_USAGE
    struct ceph_san_source_info *source;
#endif
    needed_size = round_up(needed_size + sizeof(struct ceph_san_log_entry), 8);
#if CEPH_SAN_TRACK_USAGE
    /* Get source info to update stats */
    source = ceph_san_get_source_info(source_id);
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
        ctx = ceph_san_get_ctx();
        if (!ctx) {
            pr_err("Failed to get TLS context\n");
            return NULL;
        }
        if (!is_valid_kernel_addr(ctx)) {
            pr_err("ceph_san_log: invalid TLS context address: %pK\n", ctx);
            return NULL;
        }
        if (unlikely(retry_count)) {
            pr_debug("[%d]Retrying allocation with ctx %llu (%s, pid %d) (retry %d, needed_size=%zu @ %d)\n",
                     smp_processor_id(), ctx->id, ctx->comm, ctx->pid, retry_count, needed_size, source_id);
        }

        alloc = cephsan_pagefrag_alloc(&ctx->pf, needed_size);
        if (alloc == (u64)-ENOMEM) {
            pr_debug("[%d]ceph_san_log: pagefrag full for ctx %llu (%s, pid %d), refcount=%d. Alloc failed (retry=%d): pf head=%u active_elements=%d alloc_count=%u, needed_size=%zu, pagefrag_size=%u\n",
                   smp_processor_id(),
                   ctx->id, ctx->comm, ctx->pid, atomic_read(&ctx->refcount), retry_count, ctx->pf.head,
                   ctx->pf.active_elements, ctx->pf.alloc_count,
                   needed_size, CEPHSAN_PAGEFRAG_SIZE);

            /* Invalidate the correct active context slot before releasing and retrying */
            if (in_serving_softirq()) {
                if (this_cpu_read(g_logger.napi_ctxs) == ctx) {
                    pr_debug("[%d]ceph_san_log: Clearing NAPI slot for ctx %llu (CPU %d) due to ENOMEM.\n", smp_processor_id(), ctx->id, smp_processor_id());
                    this_cpu_write(g_logger.napi_ctxs, NULL);
                } else {
                    pr_warn("[%d]ceph_san_log: ENOMEM for ctx %llu (%s, pid %d) in softirq, but it wasn't in current CPU's NAPI slot. NAPI slot holds %p. Refcount: %d.\n",
                            smp_processor_id(), ctx->id, ctx->comm, ctx->pid, this_cpu_read(g_logger.napi_ctxs), atomic_read(&ctx->refcount));
                }
            } else {
                if (current->tls_ctx == (void *)&ctx->release) {
                    pr_debug("[%d]ceph_san_log: Clearing current->tls_ctx for TLS ctx %llu due to ENOMEM.\n", smp_processor_id(), ctx->id);
                    current->tls_ctx = NULL;
                } else {
                    pr_warn("[%d]ceph_san_log: ENOMEM for ctx %llu (%s, pid %d) not in softirq, but it wasn't current->tls_ctx. current->tls_ctx is %p. Refcount: %d.\n",
                            smp_processor_id(), ctx->id, ctx->comm, ctx->pid, current->tls_ctx, atomic_read(&ctx->refcount));
                }
            }

            ++retry_count;
            ceph_san_tls_release(ctx); /* This decrements refcount, ctx may be reused or freed */
            entry = NULL; /* Ensure we loop to get a new context */
            continue;
        }
        //TODO:: remove this shit alloc should return a ptr
        entry = cephsan_pagefrag_get_ptr(&ctx->pf, alloc);
        if (unlikely(!is_valid_kernel_addr(entry))) {
            pr_debug("[%d]ceph_san_log: invalid log entry pointer: %llx from ctx %llu (%s, pid %d)\n",
                     smp_processor_id(), (unsigned long long)entry, ctx->id, ctx->comm, ctx->pid);
            ceph_san_tls_release(ctx); /* Release the context as we can't use the entry */
            entry = NULL; /* force retry to get a new context and page */
            continue;
        }
        if (unlikely(retry_count)) {
            pr_debug("[%d]Successfully allocated with ctx %llu (%s, pid %d) after %d retries (needed_size=%zu @ %d)\n",
                     smp_processor_id(), ctx->id, ctx->comm, ctx->pid, retry_count, needed_size, source_id);
        }
    }

    /* Update last_entry pointer */
    ctx->pf.last_entry = entry;

    /* Fill in entry details */
#if CEPH_SAN_DEBUG_POISON
    entry->debug_poison = CEPH_SAN_LOG_ENTRY_POISON;
#endif
    entry->ts_delta = (u32)(jiffies - ctx->base_jiffies);
    entry->source_id = (u16)source_id;
    entry->client_id = (u8)client_id;
    entry->len = (u8)needed_size;
    return entry->buffer;
}
EXPORT_SYMBOL(ceph_san_log);

/**
 * ceph_san_get_napi_ctx - Get NAPI context for current CPU
 *
 * Returns pointer to NAPI context or NULL if not set
 */
struct ceph_san_tls_ctx *ceph_san_get_napi_ctx(void)
{
    struct ceph_san_tls_ctx *ctx = this_cpu_read(g_logger.napi_ctxs);

    if (ctx) {
        if (!is_valid_active_ctx(ctx, "NAPI")) {
            pr_err("BUG: Invalid NAPI context found for CPU %d, clearing.\n", smp_processor_id());
            this_cpu_write(g_logger.napi_ctxs, NULL);
            return NULL;
        }
    }
    return ctx;
}
EXPORT_SYMBOL(ceph_san_get_napi_ctx);

/**
 * ceph_san_set_napi_ctx - Set NAPI context for current CPU
 * @ctx: Context to set
 */
void ceph_san_set_napi_ctx(struct ceph_san_tls_ctx *ctx)
{
    if (ctx && !is_valid_active_ctx(ctx, "New NAPI being set")) {
        BUG(); /* Context should be valid and refcount 1 before being set */
    }
    this_cpu_write(g_logger.napi_ctxs, ctx);
}
EXPORT_SYMBOL(ceph_san_set_napi_ctx);

/**
 * ceph_san_get_ctx - Get appropriate context based on context type
 *
 * Returns pointer to appropriate context or NULL on error
 */
struct ceph_san_tls_ctx *ceph_san_get_ctx(void)
{
    /* If we're in NAPI context, use per-CPU context */
    if (in_serving_softirq()) {
        struct ceph_san_tls_ctx *ctx = ceph_san_get_napi_ctx(); /* This validates existing NAPI ctx */
        if (ctx) {
            return ctx;
        }
        /* Create new NAPI context if none exists */
        pr_debug("ceph_san_logger: creating new NAPI context for CPU %d\n", smp_processor_id());

        ctx = get_new_ctx(); /* Get base context with refcount 0 */
        if (!ctx)
            return NULL;

        /* Set up NAPI specific parts */
        ctx->task = NULL;
        ctx->pid = 0; /* Or some other indicator like -1 or smp_processor_id() */
        snprintf(ctx->comm, TASK_COMM_LEN, "NAPI-%d", smp_processor_id());
        ctx->comm[TASK_COMM_LEN - 1] = '\0'; /* Ensure null termination */

        /* Increment refcount from 0 to 1 */
        if (atomic_inc_return(&ctx->refcount) != 1) {
            pr_err("BUG: Failed to set refcount=1 for new NAPI context id=%llu (was %d before inc)\n",
                   ctx->id, atomic_read(&ctx->refcount) - 1);
            /* TODO: Consider if ctx needs to be removed from global list or freed differently if BUGging here */
            BUG();
        }

        ceph_san_set_napi_ctx(ctx); /* Stores it in per-CPU slot and does poison check */

        pr_debug("ceph_san_logger: successfully created new NAPI context id=%llu for CPU %d\n",
               ctx->id, smp_processor_id());
        return ctx;
    }
    /* Otherwise use thread-local context */
    return ceph_san_get_tls_ctx();
}
EXPORT_SYMBOL(ceph_san_get_ctx);

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
    spin_lock_init(&g_logger.ctx_id_lock);
    atomic_set(&g_logger.next_source_id, 0);
    g_logger.next_ctx_id = 1;  /* Start IDs from 1 */

    /* Initialize per-CPU NAPI contexts */
    g_logger.napi_ctxs = alloc_percpu(struct ceph_san_tls_ctx);
    if (!g_logger.napi_ctxs) {
        pr_err("Failed to allocate per-CPU NAPI contexts\n");
        return -ENOMEM;
    }

    /* Initialize allocation batch */
    ret = ceph_san_batch_init(&g_logger.alloc_batch);
    if (ret)
        goto cleanup_napi;

    /* Initialize log batch */
    ret = ceph_san_batch_init(&g_logger.log_batch);
    if (ret)
        goto cleanup_alloc;

    return 0;

cleanup_alloc:
    ceph_san_batch_cleanup(&g_logger.alloc_batch);
cleanup_napi:
    free_percpu(g_logger.napi_ctxs);
    return ret;
}
EXPORT_SYMBOL(ceph_san_logger_init);

/**
 * ceph_san_logger_cleanup - Clean up the logging system
 */
void ceph_san_logger_cleanup(void)
{
    struct ceph_san_tls_ctx *ctx, *tmp;
    int cpu;

    /* Clean up all TLS contexts */
    spin_lock(&g_logger.lock);
    list_for_each_entry_safe(ctx, tmp, &g_logger.contexts, list) {
        list_del(&ctx->list);
        free_tls_ctx(ctx);
    }
    spin_unlock(&g_logger.lock);

    /* Clean up per-CPU NAPI contexts */
    for_each_possible_cpu(cpu) {
        ctx = per_cpu_ptr(g_logger.napi_ctxs, cpu);
        if (ctx) {
            free_tls_ctx(ctx);
        }
    }
    free_percpu(g_logger.napi_ctxs);

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
    iter->current_offset = 0; // Start from the beginning
    iter->end_offset = pf->head;
    iter->prev_offset = 0;
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

    entry = cephsan_pagefrag_get_ptr(iter->pf, iter->current_offset);

    if (!entry || !is_valid_kernel_addr(entry)) {
        pr_err("ceph_san_log_iter_next: invalid entry pointer %p\n", entry);
        return NULL;
    }

#if CEPH_SAN_DEBUG_POISON
    if (entry->debug_poison != CEPH_SAN_LOG_ENTRY_POISON || entry->len == 0) {
        if (iter->steps > iter->pf->active_elements) {
            pr_err("ceph_san_log_iter_next: invalid entry pointer %p\n", entry);
        }
        return NULL;
    }
#endif
    iter->steps++;
    iter->prev_offset = iter->current_offset;
    iter->current_offset += entry->len;

    if (iter->steps > iter->pf->active_elements || iter->current_offset > iter->end_offset) {
        pr_err("ceph_san_log_iter_next: steps: %llu, active_elements: %u, entry_len: %u\n",
               iter->steps, iter->pf->active_elements, entry->len);
        pr_err("ceph_san_log_iter_next: pagefrag details:\n"
               "  head: %u, current: %llu\n"
               "  prev_offset: %llu, end_offset: %llu\n"
               "  active_elements: %d, alloc_count: %u\n",
               iter->pf->head, iter->current_offset,
               iter->prev_offset, iter->end_offset,
               iter->pf->active_elements, iter->pf->alloc_count);
        BUG();
    }

    return entry;
}
EXPORT_SYMBOL(ceph_san_log_iter_next);


/**
 * ceph_san_log_trim - Trim the current context's pagefrag by n bytes
 * @n: number of bytes to trim from the head
 *
 * Returns 0 on success, negative error code on failure.
 */
int ceph_san_log_trim(unsigned int n)
{
    struct ceph_san_tls_ctx *ctx;
    struct ceph_san_log_entry *entry;
#if CEPH_SAN_TRACK_USAGE
    struct ceph_san_source_info *source;
#endif

    ctx = ceph_san_get_tls_ctx();
    if (!ctx)
        return -ENOMEM;

    entry = ctx->pf.last_entry;
    if (!entry)
        return -EINVAL;

    /* Get the source info to update bytes */
#if CEPH_SAN_TRACK_USAGE
    source = ceph_san_get_source_info(entry->source_id);
    if (source) {
        if (in_serving_softirq()) {
            atomic_sub(n, &source->napi_bytes);
        } else {
            atomic_sub(n, &source->task_bytes);
        }
    }
#endif

    entry->len -= n;
    cephsan_pagefrag_trim(&ctx->pf, n);
    return 0;
}
EXPORT_SYMBOL(ceph_san_log_trim);
