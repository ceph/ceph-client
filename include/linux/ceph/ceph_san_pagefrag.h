#ifndef CEPH_SAN_PAGEFRAG_H
#define CEPH_SAN_PAGEFRAG_H

#include <linux/types.h>
#include <linux/mm.h>

#define CEPHSAN_PAGEFRAG_SIZE  (1<<22)  /* 4MB */

/* Pagefrag allocator structure */
struct cephsan_pagefrag {
    struct page *pages;
    void *buffer;
    unsigned int head;
    unsigned int tail;
};

int cephsan_pagefrag_init(struct cephsan_pagefrag *pf);
int cephsan_pagefrag_init_with_buffer(struct cephsan_pagefrag *pf, void *buffer, size_t size);
u64 cephsan_pagefrag_alloc(struct cephsan_pagefrag *pf, unsigned int n);
void cephsan_pagefrag_free(struct cephsan_pagefrag *pf, unsigned int n);
void cephsan_pagefrag_deinit(struct cephsan_pagefrag *pf);
void *cephsan_pagefrag_get_ptr(struct cephsan_pagefrag *pf, u64 val);

#define CEPHSAN_PAGEFRAG_GET_N(val)  ((val) >> 32)

#endif /* CEPH_SAN_PAGEFRAG_H */
