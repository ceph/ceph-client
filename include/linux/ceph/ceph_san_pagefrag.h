#ifndef CEPH_SAN_PAGEFRAG_H
#define CEPH_SAN_PAGEFRAG_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/spinlock.h>

#define CEPHSAN_PAGEFRAG_SIZE  (1<<19)  /* 512KB */
#define CEPHSAN_PAGEFRAG_MASK (CEPHSAN_PAGEFRAG_SIZE - 1)

/* Pagefrag allocator structure */
struct cephsan_pagefrag {
    struct page *pages;
    void *buffer;
    spinlock_t lock;        /* protects head */
    unsigned int head;
    unsigned int alloc_count;
    int active_elements;
    void *last_entry;           /* Pointer to the last allocated entry */
};

int cephsan_pagefrag_init(struct cephsan_pagefrag *pf);
int cephsan_pagefrag_init_with_buffer(struct cephsan_pagefrag *pf, void *buffer, size_t size);
int cephsan_pagefrag_alloc(struct cephsan_pagefrag *pf, unsigned int n);
void *cephsan_pagefrag_get_ptr_from_tail(struct cephsan_pagefrag *pf);
void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n);
void cephsan_pagefrag_deinit(struct cephsan_pagefrag *pf);
void cephsan_pagefrag_reset(struct cephsan_pagefrag *pf);
void *cephsan_pagefrag_get_ptr(struct cephsan_pagefrag *pf, u64 val);
bool cephsan_pagefrag_is_wraparound(u64 val);

/* Get allocation size from pagefrag allocation result */
u64 cephsan_pagefrag_get_alloc_size(u64 val);

#define CEPHSAN_PAGEFRAG_GET_N(val)  ((val) >> 32)

void cephsan_pagefrag_trim_head(struct cephsan_pagefrag *pf, unsigned int n);
void cephsan_pagefrag_trim(struct cephsan_pagefrag *pf, unsigned int n);

#endif /* CEPH_SAN_PAGEFRAG_H */
