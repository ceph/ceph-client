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

#endif


#ifndef CEPH_OVERRIDE_BOOKKEEPER
#define CEPH_BOOKKEEPER_DEFINED
#define kmalloc(size, flags)	ceph_kmalloc(__FILE__, __LINE__, size, flags)
#define kzalloc(size, flags)	ceph_kmalloc(__FILE__, __LINE__, size, \
					     flags | __GFP_ZERO)
#define kcalloc(n, size, flags)	ceph_kmalloc(__FILE__, __LINE__, n * size, \
					     flags | __GFP_ZERO)
#define kstrdup(src, flags)	ceph_kstrdup(__FILE__, __LINE__, \
					              src, flags)
#define kstrndup(src, n, flags)	ceph_kstrndup(__FILE__, __LINE__, \
					              src, n, flags)
#define kfree	ceph_kfree
#endif

#ifdef CEPH_DISABLE_BOOKKEEPER
#ifdef CEPH_BOOKKEEPER_DEFINED
#undef kmalloc
#undef kzalloc
#undef kcalloc
#undef kstrdup
#undef kstrndup
#undef kfree
#endif
#endif

#endif
