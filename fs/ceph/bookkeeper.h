#ifdef CONFIG_CEPH_BOOKKEEPER

#ifndef _FS_CEPH_BOOKKEEPER_H
#define _FS_CEPH_BOOKKEEPER_H

#include <linux/module.h>

extern void ceph_bookkeeper_dump(void);
extern void ceph_bookkeeper_init(void);
extern void ceph_bookkeeper_finalize(void);

extern void *ceph_kmalloc(char *fname, int line, size_t size, gfp_t flags);
extern char *ceph_kstrdup(char *fname, int line, const char *src, gfp_t flags);
extern char *ceph_kstrndup(char *fname, int line, const char *src, int n, gfp_t flags);

extern void ceph_kfree(const void *ptr);

extern struct kmem_cache *ceph_kmem_cache_create(const char *name,
			size_t size, size_t align,
			unsigned long flags, void (*ctor)(void *));
extern void ceph_kmem_cache_destroy(struct kmem_cache *cachep);

extern void *ceph_kmem_cache_alloc(char *fname, int line, struct kmem_cache *cachep,
		           gfp_t flags);

extern void ceph_kmem_cache_free(struct kmem_cache *cachep, void *objp);
extern size_t ceph_bookkeeper_get_footprint(void);

#endif


#ifndef CEPH_OVERRIDE_BOOKKEEPER
#define CEPH_BOOKKEEPER_DEFINED
#define kmalloc(size, flags)	ceph_kmalloc(__FILE__, __LINE__, size, flags)
#define kzalloc(size, flags)	ceph_kmalloc(__FILE__, __LINE__, size, \
					     flags | __GFP_ZERO)
#define kcalloc(n, size, flags)	ceph_kmalloc(__FILE__, __LINE__, (n) * (size), \
					     flags | __GFP_ZERO)
#define kstrdup(src, flags)	ceph_kstrdup(__FILE__, __LINE__, \
					              src, flags)
#define kstrndup(src, n, flags)	ceph_kstrndup(__FILE__, __LINE__, \
					              src, n, flags)
#define kfree	ceph_kfree

#define kmem_cache_create	ceph_kmem_cache_create
#define kmem_cache_destroy	ceph_kmem_cache_destroy
#define kmem_cache_alloc(cachep, flags) \
			ceph_kmem_cache_alloc(__FILE__, __LINE__, cachep, flags)
#define kmem_cache_free		ceph_kmem_cache_free

#endif

#ifdef CEPH_DISABLE_BOOKKEEPER
#ifdef CEPH_BOOKKEEPER_DEFINED
#undef kmalloc
#undef kzalloc
#undef kcalloc
#undef kstrdup
#undef kstrndup
#undef kfree
#undef kmem_cache_create
#undef kmem_cache_destroy
#undef kmem_cache_alloc
#undef kmem_cache_free
#endif
#endif

#endif
