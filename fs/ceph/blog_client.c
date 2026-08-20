// SPDX-License-Identifier: GPL-2.0
/*
 * Ceph client ID management for BLOG integration
 *
 * Maintains mapping between Ceph's fsid/global_id and BLOG client IDs
 */

#include <linux/ceph/ceph_debug.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/jump_label.h>
#include <linux/ceph/libceph.h>
#include <linux/ceph/ceph_blog.h>
#include "blog.h"
#include "blog_module.h"

#include "super.h"

DEFINE_STATIC_KEY_FALSE(ceph_blog_key);

static int blog_max_sources = BLOG_DEFAULT_MAX_SOURCES;
static int blog_max_clients = BLOG_DEFAULT_MAX_CLIENTS;

module_param_named(blog_max_sources, blog_max_sources, int, 0444);
MODULE_PARM_DESC(blog_max_sources,
		 "Maximum BLOG source IDs per logger (load-time, default 4096)");
module_param_named(blog_max_clients, blog_max_clients, int, 0444);
MODULE_PARM_DESC(blog_max_clients,
		 "Maximum BLOG client IDs (load-time, default 256)");

int blog_param_max_sources(void)
{
	int n = READ_ONCE(blog_max_sources);

	if (n < 2)
		n = 2;
	if (n > BLOG_MAX_SOURCE_IDS_CAP)
		n = BLOG_MAX_SOURCE_IDS_CAP;
	return n;
}

int blog_param_max_clients(void)
{
	int n = READ_ONCE(blog_max_clients);

	if (n < 2)
		n = 2;
	if (n > BLOG_MAX_CLIENT_IDS_CAP)
		n = BLOG_MAX_CLIENT_IDS_CAP;
	return n;
}

/* Global client mapping state */
static struct {
	struct ceph_blog_client_info *client_map;
	/* Parallel to client_map: which ceph_client owns each slot. */
	struct ceph_client **owners;
	u32 max_clients;
	u32 next_client_id;
	spinlock_t lock;  /* protects client_map */
	bool initialized;
} ceph_blog_state = {
	.next_client_id = 1,  /* Start from 1, 0 is reserved */
	.lock = __SPIN_LOCK_UNLOCKED(ceph_blog_state.lock),
	.initialized = false,
};

static bool ceph_blog_ids_match(const struct ceph_blog_client_info *entry,
				     const char *fsid, u64 global_id)
{
	if (!entry)
		return false;
	if (entry->global_id != global_id)
		return false;
	return !memcmp(entry->fsid, fsid, sizeof(entry->fsid));
}

static bool ceph_blog_client_slot_free(const struct ceph_blog_client_info *entry)
{
	return !data_race(entry->global_id) &&
	       !data_race(memchr_inv(entry->fsid, 0, sizeof(entry->fsid)));
}

int ceph_blog_init(void)
{
	u32 max_clients;
	int ret;

	if (ceph_blog_state.initialized)
		return 0;

	ret = blog_module_wq_init();
	if (ret)
		return ret;

	max_clients = blog_param_max_clients();
	ceph_blog_state.client_map = kcalloc(max_clients,
					     sizeof(*ceph_blog_state.client_map),
					     GFP_KERNEL);
	if (!ceph_blog_state.client_map) {
		blog_module_wq_exit();
		return -ENOMEM;
	}
	ceph_blog_state.owners = kcalloc(max_clients,
					 sizeof(*ceph_blog_state.owners),
					 GFP_KERNEL);
	if (!ceph_blog_state.owners) {
		kfree(ceph_blog_state.client_map);
		ceph_blog_state.client_map = NULL;
		blog_module_wq_exit();
		return -ENOMEM;
	}

	ceph_blog_state.max_clients = max_clients;
	ceph_blog_state.next_client_id = 1;
	ceph_blog_state.initialized = true;

	pr_debug("ceph: BLOG client mapping initialized (max_clients=%u)\n",
		 max_clients);
	return 0;
}

void ceph_blog_cleanup(void)
{
	void *client_map = NULL;
	void *owners = NULL;

	blog_module_flush_frees();

	if (ceph_blog_state.initialized) {
		spin_lock(&ceph_blog_state.lock);
		client_map = ceph_blog_state.client_map;
		ceph_blog_state.client_map = NULL;
		owners = ceph_blog_state.owners;
		ceph_blog_state.owners = NULL;
		ceph_blog_state.max_clients = 0;
		ceph_blog_state.next_client_id = 1;
		ceph_blog_state.initialized = false;
		spin_unlock(&ceph_blog_state.lock);
		kfree(client_map);
		kfree(owners);
		pr_debug("ceph: BLOG client mapping cleaned up\n");
	}

	blog_module_wq_exit();
}

int ceph_blog_fsc_init(struct ceph_fs_client *fsc)
{
	if (!fsc)
		return -EINVAL;

	mutex_init(&fsc->blog_mutex);
	RCU_INIT_POINTER(fsc->blog_ctx, NULL);
	WRITE_ONCE(fsc->blog_enabled, false);
	return 0;
}

int ceph_blog_set_enabled(struct ceph_fs_client *fsc, bool enabled)
{
	struct blog_module_context *ctx;
	bool was_enabled;
	int ret = 0;

	if (!fsc)
		return -EINVAL;

	mutex_lock(&fsc->blog_mutex);
	was_enabled = READ_ONCE(fsc->blog_enabled);
	ctx = rcu_dereference_protected(fsc->blog_ctx,
					lockdep_is_held(&fsc->blog_mutex));
	if (enabled && !ctx) {
		ctx = blog_module_init("ceph");
		if (!ctx) {
			pr_err("ceph: failed to initialize BLOG context for fs client\n");
			ret = -ENOMEM;
			goto out;
		}
		rcu_assign_pointer(fsc->blog_ctx, ctx);
	}
	WRITE_ONCE(fsc->blog_enabled, enabled);
	if (enabled && !was_enabled)
		static_branch_inc(&ceph_blog_key);
	else if (!enabled && was_enabled)
		static_branch_dec(&ceph_blog_key);
out:
	mutex_unlock(&fsc->blog_mutex);
	return ret;
}

void ceph_blog_fsc_cleanup(struct ceph_fs_client *fsc)
{
	struct blog_module_context *ctx;
	bool was_enabled;

	if (!fsc)
		return;

	mutex_lock(&fsc->blog_mutex);
	was_enabled = READ_ONCE(fsc->blog_enabled);
	WRITE_ONCE(fsc->blog_enabled, false);
	if (was_enabled)
		static_branch_dec(&ceph_blog_key);
	ctx = rcu_replace_pointer(fsc->blog_ctx, NULL,
				  lockdep_is_held(&fsc->blog_mutex));
	mutex_unlock(&fsc->blog_mutex);

	if (ctx) {
		synchronize_rcu();
		blog_module_put(ctx);
		blog_module_flush_frees();
	}
}

bool ceph_blog_is_enabled(struct ceph_fs_client *fsc)
{
	struct blog_module_context *ctx;
	bool enabled = false;

	if (!fsc || !READ_ONCE(fsc->blog_enabled))
		return false;

	rcu_read_lock();
	ctx = rcu_dereference(fsc->blog_ctx);
	if (ctx && READ_ONCE(ctx->logger))
		enabled = true;
	rcu_read_unlock();

	return enabled;
}

struct blog_tls_ctx *ceph_blog_acquire_ctx(struct ceph_fs_client *fsc,
					   gfp_t gfp,
					   struct blog_module_context **held_mod)
{
	struct blog_module_context *ctx;
	struct blog_tls_ctx *tls_ctx = NULL;

	if (held_mod)
		*held_mod = NULL;

	if (!fsc || !READ_ONCE(fsc->blog_enabled))
		return NULL;

	rcu_read_lock();
	ctx = rcu_dereference(fsc->blog_ctx);
	if (!ctx || !READ_ONCE(ctx->logger)) {
		rcu_read_unlock();
		return NULL;
	}

	if (!gfpflags_allow_blocking(gfp)) {
		/*
		 * Non-blocking: reuse an existing per-task ctx only.  Do not
		 * pin the module until lookup hits. A miss must not call
		 * blog_module_put(), which can sleep in blog_module_free().
		 */
		tls_ctx = blog_lookup_tls_ctx(ctx);
		if (!tls_ctx || !refcount_inc_not_zero(&ctx->refcount)) {
			rcu_read_unlock();
			return NULL;
		}
		rcu_read_unlock();
		goto hold;
	}

	if (!refcount_inc_not_zero(&ctx->refcount)) {
		rcu_read_unlock();
		return NULL;
	}
	rcu_read_unlock();

	tls_ctx = blog_get_tls_ctx_ctx(ctx, gfp);
	if (!tls_ctx) {
		blog_module_put(ctx);
		return NULL;
	}

hold:
	/* Keep the module ref for the enter-exit window; put via blog_mod. */
	if (held_mod)
		*held_mod = ctx;
	else
		blog_module_put(ctx);

	return tls_ctx;
}

void ceph_blog_module_put(struct blog_module_context *ctx)
{
	blog_module_put(ctx);
}

struct ceph_blog_cpu_cache {
	struct task_struct *task;
	struct blog_tls_ctx *ctx;
};

static DEFINE_PER_CPU(struct ceph_blog_cpu_cache, ceph_blog_cpu_cache);

static void blog_cpu_cache_clear_slot(struct blog_tls_ctx *ctx, int cpu)
{
	struct ceph_blog_cpu_cache *c;

	if (cpu < 0)
		return;
	c = per_cpu_ptr(&ceph_blog_cpu_cache, cpu);
	if (READ_ONCE(c->ctx) == ctx) {
		WRITE_ONCE(c->task, NULL);
		WRITE_ONCE(c->ctx, NULL);
	}
}

/*
 * Drop published per-CPU slots for @ctx before GC/retire can free it.
 * With the single-slot invariant, clearing cache_cpu (and this CPU) is enough.
 */
void ceph_blog_cpu_clear(struct blog_tls_ctx *ctx)
{
	int cpu;

	if (!ctx)
		return;

	preempt_disable();
	cpu = READ_ONCE(ctx->cache_cpu);
	blog_cpu_cache_clear_slot(ctx, cpu);
	if (cpu != smp_processor_id())
		blog_cpu_cache_clear_slot(ctx, smp_processor_id());
	WRITE_ONCE(ctx->cache_cpu, -1);
	preempt_enable();
}

void ceph_blog_cpu_bind(struct blog_tls_ctx *ctx)
{
	struct ceph_blog_cpu_cache *c;
	int cpu, prev_cpu;

	if (!ctx)
		return;

	/*
	 * Publish into the per-CPU cache under preempt_disable only.
	 * Do not migrate_disable() across the enter-exit window: on !RT
	 * that is preempt_disable and would leave preempt elevated for
	 * the whole VFS call.  Keep each ctx on at most one CPU slot:
	 * clear the prior publish before installing the new one.
	 */
	preempt_disable();
	WRITE_ONCE(ctx->enter_depth, READ_ONCE(ctx->enter_depth) + 1);
	cpu = smp_processor_id();
	prev_cpu = READ_ONCE(ctx->cache_cpu);
	if (prev_cpu >= 0 && prev_cpu != cpu)
		blog_cpu_cache_clear_slot(ctx, prev_cpu);
	c = this_cpu_ptr(&ceph_blog_cpu_cache);
	WRITE_ONCE(c->task, current);
	WRITE_ONCE(c->ctx, ctx);
	WRITE_ONCE(ctx->cache_cpu, cpu);
	preempt_enable();
}

void ceph_blog_cpu_unbind(struct blog_tls_ctx *ctx)
{
	int cpu;

	if (!ctx || !READ_ONCE(ctx->enter_depth))
		return;

	preempt_disable();
	WRITE_ONCE(ctx->enter_depth, READ_ONCE(ctx->enter_depth) - 1);
	if (!READ_ONCE(ctx->enter_depth)) {
		cpu = READ_ONCE(ctx->cache_cpu);
		blog_cpu_cache_clear_slot(ctx, cpu);
		if (cpu != smp_processor_id())
			blog_cpu_cache_clear_slot(ctx, smp_processor_id());
		WRITE_ONCE(ctx->cache_cpu, -1);
	}
	preempt_enable();
}

struct blog_tls_ctx *ceph_blog_get_cached_ctx(struct ceph_fs_client *fsc)
{
	struct ceph_blog_cpu_cache *c;
	struct blog_tls_ctx *ctx = NULL;
	struct blog_module_context *mod;
	struct ceph_journal_info *ji;
	struct blog_logger *want_logger;
	int cpu, prev_cpu;

	if (!fsc)
		return NULL;

	rcu_read_lock();
	mod = rcu_dereference(fsc->blog_ctx);
	want_logger = (mod && mod->logger) ? mod->logger : NULL;
	if (!want_logger) {
		rcu_read_unlock();
		return NULL;
	}

	preempt_disable();
	c = this_cpu_ptr(&ceph_blog_cpu_cache);
	if (likely(READ_ONCE(c->task) == current) && READ_ONCE(c->ctx)) {
		ctx = READ_ONCE(c->ctx);
		if (READ_ONCE(ctx->task) == current &&
		    READ_ONCE(ctx->enter_depth) &&
		    ctx->logger == want_logger)
			; /* hit. Mount-scoped */
		else {
			WRITE_ONCE(c->task, NULL);
			WRITE_ONCE(c->ctx, NULL);
			ctx = NULL;
		}
	}
	preempt_enable();
	if (ctx) {
		rcu_read_unlock();
		return ctx;
	}

	/*
	 * Cache miss after preemption.  Prefer the mount-scoped
	 * journal_info ctx when it matches @fsc so nested multi-mount
	 * work does not attach to another mount's logger.  Plain
	 * ceph_blog_enter() never installs journal_info. Recover only
	 * from @fsc's own task map (not a cross-mount module-list walk).
	 */
	ji = ceph_ji_from_current();
	if (ji && ceph_ji_matches_fsc(ji, fsc)) {
		if (ji->blog_ctx &&
		    READ_ONCE(ji->blog_ctx->enter_depth) &&
		    READ_ONCE(ji->blog_ctx->task) == current &&
		    ji->blog_ctx->logger == want_logger)
			ctx = ji->blog_ctx;
	} else {
		ctx = blog_lookup_tls_ctx(mod);
		if (ctx && !(READ_ONCE(ctx->enter_depth) &&
			     READ_ONCE(ctx->task) == current))
			ctx = NULL;
	}
	rcu_read_unlock();

	if (ctx) {
		preempt_disable();
		cpu = smp_processor_id();
		prev_cpu = READ_ONCE(ctx->cache_cpu);
		if (prev_cpu >= 0 && prev_cpu != cpu)
			blog_cpu_cache_clear_slot(ctx, prev_cpu);
		c = this_cpu_ptr(&ceph_blog_cpu_cache);
		WRITE_ONCE(c->task, current);
		WRITE_ONCE(c->ctx, ctx);
		WRITE_ONCE(ctx->cache_cpu, cpu);
		preempt_enable();
		return ctx;
	}

	return NULL;
}

/**
 * ceph_blog_check_client_id - Check if a client ID matches the given fsid:global_id pair
 * @id: Client ID to check
 * @fsid: Client FSID to compare
 * @global_id: Client global ID to compare
 *
 * Returns the actual ID of the pair. If the given ID doesn't match, scans for
 * existing matches or allocates a new ID if no match is found.
 */
u32 ceph_blog_check_client_id(u32 id, const char *fsid, u64 global_id)
{
	u32 found_id = 0;
	u32 max_clients;
	struct ceph_blog_client_info *entry;

	if (unlikely(!ceph_blog_state.initialized)) {
		WARN_ON_ONCE(1);
		return 0;
	}

	spin_lock(&ceph_blog_state.lock);
	max_clients = ceph_blog_state.max_clients;

	if (id != 0 && id < max_clients) {
		entry = &ceph_blog_state.client_map[id];
		if (ceph_blog_ids_match(entry, fsid, global_id)) {
			found_id = id;
			goto out;
		}
	}

	for (id = 1; id < max_clients; id++) {
		entry = &ceph_blog_state.client_map[id];
		if (ceph_blog_ids_match(entry, fsid, global_id)) {
			found_id = id;
			goto out;
		}
	}

	if (ceph_blog_state.next_client_id < max_clients) {
		found_id = ceph_blog_state.next_client_id++;
	} else {
		found_id = 0;
		for (id = 1; id < max_clients; id++) {
			entry = &ceph_blog_state.client_map[id];
			if (ceph_blog_client_slot_free(entry)) {
				found_id = id;
				break;
			}
		}
		if (!found_id) {
			pr_warn_once("ceph: BLOG client ID space exhausted\n");
			goto out;
		}
	}

	entry = &ceph_blog_state.client_map[found_id];
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->fsid, fsid, sizeof(entry->fsid));
	entry->global_id = global_id;

out:
	spin_unlock(&ceph_blog_state.lock);
	return found_id;
}

/**
 * ceph_blog_get_client_info - Get client info for a given ID
 * @id: Client ID
 *
 * Reads client_map[] without holding ceph_blog_state.lock.
 * Writers store fields under the lock. Callers accept the benign
 * race: a concurrent slot release and reuse may cause old log
 * entries to show a new client's identity; the impact is cosmetic.
 */
const struct ceph_blog_client_info *ceph_blog_get_client_info(u32 id)
{
	const struct ceph_blog_client_info *entry;

	if (!READ_ONCE(ceph_blog_state.initialized) ||
	    id == 0 || id >= READ_ONCE(ceph_blog_state.max_clients))
		return NULL;
	entry = &ceph_blog_state.client_map[id];
	/* Freed/zeroed slots must not deserialize as a valid client. */
	if (ceph_blog_client_slot_free(entry))
		return NULL;
	return entry;
}

int ceph_blog_client_des_callback(char *buf, size_t size, u8 client_id)
{
	const struct ceph_blog_client_info *info;
	char fsid[16];
	u64 global_id;

	if (!buf || !size)
		return -EINVAL;
	if (client_id == 0)
		return 0;

	info = ceph_blog_get_client_info(client_id);
	if (!info)
		return snprintf(buf, size, "[unknown_client_%u]", client_id);

	global_id = data_race(info->global_id);
	data_race(memcpy(fsid, info->fsid, sizeof(fsid)));
	return snprintf(buf, size, "[%pU %llu] ", fsid, global_id);
}

u32 ceph_blog_get_client_id(struct ceph_client *client)
{
	u32 cached;
	u32 id;

	if (!client)
		return 0;
	if (!client->monc.auth)
		return 0;

	cached = READ_ONCE(client->blog_client_id);

	id = ceph_blog_check_client_id(cached,
				       client->fsid.fsid,
				       client->monc.auth->global_id);
	if (!id)
		return 0;

	/*
	 * Record ownership of the (possibly new) slot.  On auth rekey do
	 * not clear the prior map entry: buffered records still carry the
	 * old client_id and resolve it lazily on readback.  All of this
	 * client's slots are freed in ceph_blog_release_client_id() before
	 * fsc cleanup tears down the buffers.
	 */
	spin_lock(&ceph_blog_state.lock);
	if (ceph_blog_state.initialized &&
	    id < ceph_blog_state.max_clients)
		ceph_blog_state.owners[id] = client;
	spin_unlock(&ceph_blog_state.lock);

	if (cached != id)
		WRITE_ONCE(client->blog_client_id, id);

	return id;
}

/**
 * ceph_blog_release_client_id - Free a client's BLOG ID mapping slots
 * @client: Ceph client being torn down
 *
 * Clears the cached ID on @client and zeroes every global map entry this
 * client owns (including slots left behind by auth rekey) so the 8-bit
 * namespace can be reused after remounts / new auth sessions.
 */
void ceph_blog_release_client_id(struct ceph_client *client)
{
	u32 id;

	if (!client)
		return;

	WRITE_ONCE(client->blog_client_id, 0);

	spin_lock(&ceph_blog_state.lock);
	if (!ceph_blog_state.initialized) {
		spin_unlock(&ceph_blog_state.lock);
		return;
	}
	for (id = 1; id < ceph_blog_state.max_clients; id++) {
		if (ceph_blog_state.owners[id] != client)
			continue;
		ceph_blog_state.owners[id] = NULL;
		memset(&ceph_blog_state.client_map[id], 0,
		       sizeof(*ceph_blog_state.client_map));
	}
	spin_unlock(&ceph_blog_state.lock);
}
