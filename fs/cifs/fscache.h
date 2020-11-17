/* SPDX-License-Identifier: LGPL-2.1 */
/*
 *   CIFS filesystem cache interface definitions
 *
 *   Copyright (c) 2010 Novell, Inc.
 *   Authors(s): Suresh Jayaraman (sjayaraman@suse.de>
 *
 */
#ifndef _CIFS_FSCACHE_H
#define _CIFS_FSCACHE_H

#include <linux/fscache.h>

#include "cifsglob.h"

/*
 * Auxiliary data attached to CIFS superblock within the cache
 */
struct cifs_fscache_super_auxdata {
	u64	resource_id;		/* unique server resource id */
	__le64	vol_create_time;
	u32	vol_serial_number;
} __packed;

/*
 * Auxiliary data attached to CIFS inode within the cache
 */
struct cifs_fscache_inode_auxdata {
	u64 last_write_time_sec;
	u64 last_change_time_sec;
	u32 last_write_time_nsec;
	u32 last_change_time_nsec;
};

#ifdef CONFIG_CIFS_FSCACHE

/*
 * fscache.c
 */
extern void cifs_fscache_get_super_cookie(struct cifs_tcon *);
extern void cifs_fscache_release_super_cookie(struct cifs_tcon *);

extern void cifs_fscache_get_inode_cookie(struct inode *);
extern void cifs_fscache_release_inode_cookie(struct inode *);
extern void cifs_fscache_unuse_inode_cookie(struct inode *, bool);

static inline
void cifs_fscache_fill_auxdata(struct inode *inode,
			       struct cifs_fscache_inode_auxdata *auxdata)
{
	struct cifsInodeInfo *cifsi = CIFS_I(inode);

	memset(&auxdata, 0, sizeof(auxdata));
	auxdata->last_write_time_sec   = cifsi->vfs_inode.i_mtime.tv_sec;
	auxdata->last_write_time_nsec  = cifsi->vfs_inode.i_mtime.tv_nsec;
	auxdata->last_change_time_sec  = cifsi->vfs_inode.i_ctime.tv_sec;
	auxdata->last_change_time_nsec = cifsi->vfs_inode.i_ctime.tv_nsec;
}


extern int cifs_fscache_release_page(struct page *page, gfp_t gfp);
extern int __cifs_readpage_from_fscache(struct inode *, struct page *);
extern int __cifs_readpages_from_fscache(struct inode *,
					 struct address_space *,
					 struct list_head *,
					 unsigned *);
extern void __cifs_readpage_to_fscache(struct inode *, struct page *);

static inline struct fscache_cookie *cifs_inode_cookie(struct inode *inode)
{
	return CIFS_I(inode)->fscache;
}

static inline int cifs_readpage_from_fscache(struct inode *inode,
					     struct page *page)
{
	if (CIFS_I(inode)->fscache)
		return __cifs_readpage_from_fscache(inode, page);

	return -ENOBUFS;
}

static inline int cifs_readpages_from_fscache(struct inode *inode,
					      struct address_space *mapping,
					      struct list_head *pages,
					      unsigned *nr_pages)
{
	if (CIFS_I(inode)->fscache)
		return __cifs_readpages_from_fscache(inode, mapping, pages,
						     nr_pages);
	return -ENOBUFS;
}

static inline void cifs_readpage_to_fscache(struct inode *inode,
					    struct page *page)
{
	if (PageFsCache(page))
		__cifs_readpage_to_fscache(inode, page);
}

#else /* CONFIG_CIFS_FSCACHE */
static inline
void cifs_fscache_fill_auxdata(struct inode *inode,
			       struct cifs_fscache_inode_auxdata *auxdata)
{
}

static inline void cifs_fscache_get_super_cookie(struct cifs_tcon *tcon) {}
static inline void cifs_fscache_release_super_cookie(struct cifs_tcon *tcon) {}

static inline void cifs_fscache_get_inode_cookie(struct inode *inode) {}
static inline void cifs_fscache_release_inode_cookie(struct inode *inode) {}
static inline void cifs_fscache_unuse_inode_cookie(struct inode *inode, bool update) {}
static inline struct fscache_cookie *cifs_inode_cookie(struct inode *inode) { return NULL; }

static inline int
cifs_readpage_from_fscache(struct inode *inode, struct page *page)
{
	return -ENOBUFS;
}

static inline int cifs_readpages_from_fscache(struct inode *inode,
					      struct address_space *mapping,
					      struct list_head *pages,
					      unsigned *nr_pages)
{
	return -ENOBUFS;
}

static inline void cifs_readpage_to_fscache(struct inode *inode,
			struct page *page) {}

#endif /* CONFIG_CIFS_FSCACHE */

#endif /* _CIFS_FSCACHE_H */
