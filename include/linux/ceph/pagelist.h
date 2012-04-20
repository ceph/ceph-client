#ifndef __FS_CEPH_PAGELIST_H
#define __FS_CEPH_PAGELIST_H

#include <linux/list.h>

struct ceph_pagelist {
	struct list_head head;
	void *mapped_tail;
	size_t length;
	size_t room;
	struct list_head free_list;
	size_t num_pages_free;
};

struct ceph_pagelist_cursor {
	struct ceph_pagelist *pl;   /* pagelist, for error checking */
	struct list_head *page_lru; /* page in list */
	size_t room;		    /* room remaining to reset to */
};

static inline void ceph_pagelist_init(struct ceph_pagelist *pl)
{
	INIT_LIST_HEAD(&pl->head);
	pl->mapped_tail = NULL;
	pl->length = 0;
	pl->room = 0;
	INIT_LIST_HEAD(&pl->free_list);
	pl->num_pages_free = 0;
}

extern int ceph_pagelist_release(struct ceph_pagelist *pl);

extern int ceph_pagelist_append(struct ceph_pagelist *pl, const void *d, size_t l);

extern int ceph_pagelist_reserve(struct ceph_pagelist *pl, size_t space);

extern int ceph_pagelist_free_reserve(struct ceph_pagelist *pl);

extern void ceph_pagelist_set_cursor(struct ceph_pagelist *pl,
				     struct ceph_pagelist_cursor *c);

extern int ceph_pagelist_truncate(struct ceph_pagelist *pl,
				  struct ceph_pagelist_cursor *c);

#endif
