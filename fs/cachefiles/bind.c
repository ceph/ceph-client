// SPDX-License-Identifier: GPL-2.0-or-later
/* Bind and unbind a cache from the filesystem backing it
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/ctype.h>
#include <linux/xattr.h>
#include "internal.h"

static int cachefiles_daemon_add_cache(struct cachefiles_cache *caches);

/*
 * bind a directory as a cache
 */
int cachefiles_daemon_bind(struct cachefiles_cache *cache, char *args)
{
	_enter("{%u,%u,%u,%u,%u,%u},%s",
	       cache->frun_percent,
	       cache->fcull_percent,
	       cache->fstop_percent,
	       cache->brun_percent,
	       cache->bcull_percent,
	       cache->bstop_percent,
	       args);

	/* start by checking things over */
	ASSERT(cache->fstop_percent < cache->fcull_percent &&
	       cache->fcull_percent < cache->frun_percent &&
	       cache->frun_percent  < 100);

	ASSERT(cache->bstop_percent < cache->bcull_percent &&
	       cache->bcull_percent < cache->brun_percent &&
	       cache->brun_percent  < 100);

	if (*args) {
		pr_err("'bind' command doesn't take an argument\n");
		return -EINVAL;
	}

	if (!cache->rootdirname) {
		pr_err("No cache directory specified\n");
		return -EINVAL;
	}

	/* don't permit already bound caches to be re-bound */
	if (test_bit(CACHEFILES_READY, &cache->flags)) {
		pr_err("Cache already bound\n");
		return -EBUSY;
	}

	/* make sure we have copies of the tag and dirname strings */
	if (!cache->tag) {
		/* the tag string is released by the fops->release()
		 * function, so we don't release it on error here */
		cache->tag = kstrdup("CacheFiles", GFP_KERNEL);
		if (!cache->tag)
			return -ENOMEM;
	}

	/* add the cache */
	return cachefiles_daemon_add_cache(cache);
}

/*
 * add a cache
 */
static int cachefiles_daemon_add_cache(struct cachefiles_cache *cache)
{
	struct path path;
	struct kstatfs stats;
	struct dentry *root;
	const struct cred *saved_cred;
	int ret;

	_enter("");

	/* we want to work under the module's security ID */
	ret = cachefiles_get_security_ID(cache);
	if (ret < 0)
		return ret;

	cachefiles_begin_secure(cache, &saved_cred);

	/* look up the directory at the root of the cache */
	ret = kern_path(cache->rootdirname, LOOKUP_DIRECTORY, &path);
	if (ret < 0)
		goto error_open_root;

	cache->mnt = path.mnt;
	root = path.dentry;

	ret = -EINVAL;
	if (mnt_user_ns(path.mnt) != &init_user_ns) {
		pr_warn("File cache on idmapped mounts not supported");
		goto error_unsupported;
	}

	/* check parameters */
	ret = -EOPNOTSUPP;
	if (d_is_negative(root) ||
	    !d_backing_inode(root)->i_op->lookup ||
	    !d_backing_inode(root)->i_op->mkdir ||
	    !(d_backing_inode(root)->i_opflags & IOP_XATTR) ||
	    !root->d_sb->s_op->statfs ||
	    !root->d_sb->s_op->sync_fs)
		goto error_unsupported;

	ret = -EROFS;
	if (sb_rdonly(root->d_sb))
		goto error_unsupported;

	/* determine the security of the on-disk cache as this governs
	 * security ID of files we create */
	ret = cachefiles_determine_cache_security(cache, root, &saved_cred);
	if (ret < 0)
		goto error_unsupported;

	/* get the cache size and blocksize */
	ret = vfs_statfs(&path, &stats);
	if (ret < 0)
		goto error_unsupported;

	ret = -ERANGE;
	if (stats.f_bsize <= 0)
		goto error_unsupported;

	ret = -EOPNOTSUPP;
	if (stats.f_bsize > PAGE_SIZE)
		goto error_unsupported;

	cache->bsize = stats.f_bsize;
	cache->bshift = 0;
	if (stats.f_bsize < PAGE_SIZE)
		cache->bshift = PAGE_SHIFT - ilog2(stats.f_bsize);

	_debug("blksize %u (shift %u)",
	       cache->bsize, cache->bshift);

	_debug("size %llu, avail %llu",
	       (unsigned long long) stats.f_blocks,
	       (unsigned long long) stats.f_bavail);

	/* set up caching limits */
	do_div(stats.f_files, 100);
	cache->fstop = stats.f_files * cache->fstop_percent;
	cache->fcull = stats.f_files * cache->fcull_percent;
	cache->frun  = stats.f_files * cache->frun_percent;

	_debug("limits {%llu,%llu,%llu} files",
	       (unsigned long long) cache->frun,
	       (unsigned long long) cache->fcull,
	       (unsigned long long) cache->fstop);

	stats.f_blocks >>= cache->bshift;
	do_div(stats.f_blocks, 100);
	cache->bstop = stats.f_blocks * cache->bstop_percent;
	cache->bcull = stats.f_blocks * cache->bcull_percent;
	cache->brun  = stats.f_blocks * cache->brun_percent;

	_debug("limits {%llu,%llu,%llu} blocks",
	       (unsigned long long) cache->brun,
	       (unsigned long long) cache->bcull,
	       (unsigned long long) cache->bstop);

	// PLACEHOLDER: Register with fscache
	ret = -ENOANO;
	goto error_unsupported;

error_unsupported:
	mntput(cache->mnt);
	cache->mnt = NULL;
	dput(root);
error_open_root:
	cachefiles_end_secure(cache, saved_cred);
	pr_err("Failed to register: %d\n", ret);
	return ret;
}

/*
 * unbind a cache on fd release
 */
void cachefiles_daemon_unbind(struct cachefiles_cache *cache)
{
	_enter("");

	if (test_bit(CACHEFILES_READY, &cache->flags)) {
		// PLACEHOLDER: Withdraw cache
	}

	mntput(cache->mnt);

	kfree(cache->rootdirname);
	kfree(cache->secctx);
	kfree(cache->tag);

	_leave("");
}
