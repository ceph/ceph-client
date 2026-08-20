/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ceph integration with BLOG (Binary LOGging)
 *
 * Provides a shared per-call context (struct ceph_journal_info) used for
 * the narrow MDS fill-trace window (mds_req in current->journal_info) and
 * optional BLOG TLS binding via Ceph-private per-task storage / CPU cache.
 */
#ifndef CEPH_BLOG_H
#define CEPH_BLOG_H

#include <linux/sched/mm.h>
#include <linux/gfp.h>
#include <linux/jump_label.h>

/* ---------- shared journal_info carrier ---------- */

#define CEPH_JI_MAGIC	0xCE9B7081UL
#define CEPH_JI_TAG	3UL
#define CEPH_JI_TAG_MASK	3UL

struct ceph_fs_client;
struct ceph_mds_request;
struct ceph_client;
struct blog_module_context;
struct blog_tls_ctx;

/**
 * struct ceph_journal_info - per-call context stashed in journal_info
 * @magic: CEPH_JI_MAGIC, for safe type-checking when reading journal_info
 * @saved_ji: previous value of current->journal_info (restored on exit)
 * @fsc: filesystem client for this enter
 * @blog_ctx: BLOG TLS context for binary logging, or NULL
 * @blog_mod: module context ref held for @blog_ctx when this enter acquired
 *            it (NULL when ctx was inherited from a nested parent)
 * @mds_req: MDS request during ceph_fill_trace / readdir_prepopulate,
 *           or NULL.  Read by xattr.c to avoid deadlocking RPCs and
 *           to discover which capabilities were already fetched.
 *
 * Allocated on the caller's stack at every Ceph VFS entry point.
 * ceph_blog_enter_req() installs it in current->journal_info for MDS
 * fill-trace; plain ceph_blog_enter() binds BLOG without touching
 * journal_info.  ceph_blog_exit() restores journal_info when installed.
 */
struct ceph_journal_info {
	unsigned long		magic;
	void			*saved_ji;
	struct ceph_fs_client	*fsc;
	struct blog_tls_ctx	*blog_ctx;
	struct blog_module_context *blog_mod;
	struct ceph_mds_request	*mds_req;
};

/**
 * ceph_ji_from_current - safely retrieve ceph_journal_info from journal_info
 *
 * Ceph tags its journal_info pointer so foreign filesystem state can be
 * rejected without dereferencing it.  Returns the decoded pointer if the
 * tag and magic match, NULL otherwise.
 */
static inline struct ceph_journal_info *ceph_ji_from_current(void)
{
	void *journal_info = current->journal_info;
	struct ceph_journal_info *ji;

	if (((unsigned long)journal_info & CEPH_JI_TAG_MASK) != CEPH_JI_TAG)
		return NULL;
	ji = (void *)((unsigned long)journal_info & ~CEPH_JI_TAG_MASK);
	if (!ji)
		return NULL;
	if (READ_ONCE(ji->magic) == CEPH_JI_MAGIC)
		return ji;
	return NULL;
}

static inline void *ceph_ji_encode(struct ceph_journal_info *ji)
{
	WARN_ON_ONCE((unsigned long)ji & CEPH_JI_TAG_MASK);
	return (void *)((unsigned long)ji | CEPH_JI_TAG);
}

static inline bool ceph_ji_matches_fsc(const struct ceph_journal_info *ji,
				       struct ceph_fs_client *fsc)
{
	return ji && ji->fsc == fsc;
}

/**
 * ceph_current_mds_request - get this mount's in-flight MDS request
 *
 * Same-fsc helper for request introspection (e.g. getattr mask).
 * Returns NULL outside fill-trace or when the tagged journal_info
 * belongs to a different ceph_fs_client.
 */
static inline struct ceph_mds_request *
ceph_current_mds_request(struct ceph_fs_client *fsc)
{
	struct ceph_journal_info *ji = ceph_ji_from_current();

	return ceph_ji_matches_fsc(ji, fsc) ? ji->mds_req : NULL;
}

/**
 * ceph_current_fill_trace_request - any in-flight Ceph fill-trace on this task
 *
 * Sync xattr recursion must stay task-scoped: a security hook on a
 * second Ceph mount during handle_reply() -> ceph_fill_trace() still
 * has to return -EBUSY.  Do not use the same-fsc helper for that guard.
 */
static inline struct ceph_mds_request *
ceph_current_fill_trace_request(void)
{
	struct ceph_journal_info *ji = ceph_ji_from_current();

	return ji ? ji->mds_req : NULL;
}

/* ---------- client ID mapping ---------- */

struct ceph_blog_client_info {
	char fsid[16];
	u64 global_id;
};

#ifdef CONFIG_DEBUG_FS
extern struct static_key_false ceph_blog_key;

int  ceph_blog_init(void);
void ceph_blog_cleanup(void);
int  ceph_blog_fsc_init(struct ceph_fs_client *fsc);
void ceph_blog_fsc_cleanup(struct ceph_fs_client *fsc);
int  ceph_blog_set_enabled(struct ceph_fs_client *fsc, bool enabled);
u32  ceph_blog_check_client_id(u32 id, const char *fsid, u64 global_id);
u32  ceph_blog_get_client_id(struct ceph_client *client);
void ceph_blog_release_client_id(struct ceph_client *client);
const struct ceph_blog_client_info *ceph_blog_get_client_info(u32 id);
int  ceph_blog_client_des_callback(char *buf, size_t size, u8 client_id);
bool ceph_blog_is_enabled(struct ceph_fs_client *fsc);
struct blog_tls_ctx *ceph_blog_acquire_ctx(struct ceph_fs_client *fsc,
					   gfp_t gfp,
					   struct blog_module_context **held_mod);
void ceph_blog_module_put(struct blog_module_context *ctx);
void ceph_blog_cpu_bind(struct blog_tls_ctx *ctx);
void ceph_blog_cpu_unbind(struct blog_tls_ctx *ctx);
void ceph_blog_cpu_clear(struct blog_tls_ctx *ctx);
struct blog_tls_ctx *ceph_blog_get_cached_ctx(struct ceph_fs_client *fsc);
#else
/* CONFIG_DEBUG_FS=n: BLOG objects are not linked; stubs below. */

static inline int ceph_blog_init(void) { return 0; }
static inline void ceph_blog_cleanup(void) {}
static inline int ceph_blog_fsc_init(struct ceph_fs_client *fsc) { return 0; }
static inline void ceph_blog_fsc_cleanup(struct ceph_fs_client *fsc) {}
static inline int ceph_blog_set_enabled(struct ceph_fs_client *fsc, bool enabled)
{
	return 0;
}
static inline u32 ceph_blog_check_client_id(u32 id, const char *fsid,
					    u64 global_id)
{
	return 0;
}
static inline u32 ceph_blog_get_client_id(struct ceph_client *client)
{
	return 0;
}
static inline void ceph_blog_release_client_id(struct ceph_client *client) {}
static inline const struct ceph_blog_client_info *
ceph_blog_get_client_info(u32 id)
{
	return NULL;
}
static inline int ceph_blog_client_des_callback(char *buf, size_t size,
						u8 client_id)
{
	return 0;
}
static inline bool ceph_blog_is_enabled(struct ceph_fs_client *fsc)
{
	return false;
}
static inline struct blog_tls_ctx *
ceph_blog_acquire_ctx(struct ceph_fs_client *fsc, gfp_t gfp,
		      struct blog_module_context **held_mod)
{
	if (held_mod)
		*held_mod = NULL;
	return NULL;
}
static inline void ceph_blog_module_put(struct blog_module_context *ctx) {}
static inline void ceph_blog_cpu_bind(struct blog_tls_ctx *ctx) {}
static inline void ceph_blog_cpu_unbind(struct blog_tls_ctx *ctx) {}
static inline void ceph_blog_cpu_clear(struct blog_tls_ctx *ctx) {}
static inline struct blog_tls_ctx *
ceph_blog_get_cached_ctx(struct ceph_fs_client *fsc)
{
	return NULL;
}
#endif

/* ---------- entry / exit helpers ---------- */

/**
 * ceph_blog_enter_req_gfp - bind optional BLOG ctx; install journal_info for MDS
 * @gfp: GFP_NOFS for sleepable VFS paths; GFP_ATOMIC (or any non-blocking
 *       combination) for callbacks that must not sleep.  Non-blocking
 *       acquires only reuse an existing per-task context; first-touch
 *       allocation is skipped and logging is a no-op for that enter.
 *
 * BLOG state lives in the per-task map and CPU cache.  Plain VFS enters
 * never publish into current->journal_info.  Only enter_req (MDS
 * fill-trace, which already runs under memalloc_nofs_save) installs the
 * tagged carrier so xattr paths can see mds_req.
 */
static inline void ceph_blog_enter_req_gfp(struct ceph_fs_client *fsc,
					   struct ceph_journal_info *ji,
					   struct ceph_mds_request *req,
					   gfp_t gfp)
{
	struct ceph_journal_info *parent = ceph_ji_from_current();

	ji->magic    = CEPH_JI_MAGIC;
	ji->saved_ji = current->journal_info;
	ji->fsc      = fsc;
	ji->mds_req  = req;
	ji->blog_mod = NULL;
	ji->blog_ctx = ceph_ji_matches_fsc(parent, fsc) ? parent->blog_ctx : NULL;

	if (!ji->blog_ctx && ceph_blog_is_enabled(fsc))
		ji->blog_ctx = ceph_blog_acquire_ctx(fsc, gfp, &ji->blog_mod);

	if (ji->blog_ctx)
		ceph_blog_cpu_bind(ji->blog_ctx);

	/* MDS fill-trace only: keep journal_info off reclaimable VFS paths. */
	if (req)
		current->journal_info = ceph_ji_encode(ji);
}

static inline void ceph_blog_enter_req(struct ceph_fs_client *fsc,
				       struct ceph_journal_info *ji,
				       struct ceph_mds_request *req)
{
	ceph_blog_enter_req_gfp(fsc, ji, req, GFP_NOFS);
}

static inline void ceph_blog_enter_gfp(struct ceph_fs_client *fsc,
				       struct ceph_journal_info *ji,
				       gfp_t gfp)
{
	struct ceph_journal_info *parent = ceph_ji_from_current();
	struct ceph_mds_request *req =
		ceph_ji_matches_fsc(parent, fsc) ? parent->mds_req : NULL;

	ceph_blog_enter_req_gfp(fsc, ji, req, gfp);
}

static inline void ceph_blog_enter(struct ceph_fs_client *fsc,
				   struct ceph_journal_info *ji)
{
	ceph_blog_enter_gfp(fsc, ji, GFP_NOFS);
}

/**
 * ceph_blog_exit - call at every Ceph VFS exit point
 * @ji: the same struct passed to ceph_blog_enter()
 */
static inline void ceph_blog_exit(struct ceph_journal_info *ji)
{
	if (ji->blog_ctx)
		ceph_blog_cpu_unbind(ji->blog_ctx);

	if (ji->blog_mod) {
		ceph_blog_module_put(ji->blog_mod);
		ji->blog_mod = NULL;
	}

	if (current->journal_info == ceph_ji_encode(ji))
		current->journal_info = ji->saved_ji;
}

/* ---------- debugfs ---------- */

#ifdef CONFIG_DEBUG_FS
int  ceph_blog_debugfs_init(struct ceph_fs_client *fsc);
void ceph_blog_debugfs_cleanup(struct ceph_fs_client *fsc);
#else
static inline int  ceph_blog_debugfs_init(struct ceph_fs_client *fsc) { return 0; }
static inline void ceph_blog_debugfs_cleanup(struct ceph_fs_client *fsc) {}
#endif

#endif /* CEPH_BLOG_H */
