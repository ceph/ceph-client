// SPDX-License-Identifier: GPL-2.0-only
/*
 * V9FS cache definitions.
 *
 *  Copyright (C) 2009 by Abhishek Kulkarni <adkulkar@umail.iu.edu>
 */

#include <linux/jiffies.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/9p/9p.h>

#include "v9fs.h"
#include "cache.h"

void v9fs_cache_session_get_cookie(struct v9fs_session_info *v9ses,
				   const char *dev_name)
{
	char *name, *p;

	name = kasprintf(GFP_KERNEL, "9p,%s,%s",
			 dev_name, v9ses->cachetag ?: v9ses->aname);
	if (!name)
		return;

	for (p = name; *p; p++)
		if (*p == '/')
			*p = ';';

	v9ses->fscache = fscache_acquire_volume(name, NULL, 0);
	p9_debug(P9_DEBUG_FSC, "session %p get volume %p (%s)\n",
		 v9ses, v9ses->fscache, name);
	kfree(name);
}

void v9fs_cache_inode_get_cookie(struct inode *inode)
{
	struct v9fs_inode *v9inode;
	struct v9fs_session_info *v9ses;

	if (!S_ISREG(inode->i_mode))
		return;

	v9inode = V9FS_I(inode);
	if (WARN_ON(v9inode->fscache))
		return;

	v9ses = v9fs_inode2v9ses(inode);
	v9inode->fscache =
		fscache_acquire_cookie(v9fs_session_cache(v9ses),
				       0,
				       &v9inode->qid.path,
				       sizeof(v9inode->qid.path),
				       &v9inode->qid.version,
				       sizeof(v9inode->qid.version),
				       i_size_read(&v9inode->vfs_inode));

	p9_debug(P9_DEBUG_FSC, "inode %p get cookie %p\n",
		 inode, v9inode->fscache);
}
