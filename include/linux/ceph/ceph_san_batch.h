#ifndef CEPH_SAN_BATCH_H
#define CEPH_SAN_BATCH_H

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>

/* Size of each magazine (number of elements it can hold) */
#define CEPH_SAN_MAGAZINE_SIZE 32

/* Structure representing a single magazine */
struct ceph_san_magazine {
    struct list_head list;      /* For linking in global pools */
    unsigned int count;         /* Number of elements currently in magazine */
    void *elements[CEPH_SAN_MAGAZINE_SIZE];
};

/* Per-CPU magazine state */
struct ceph_san_cpu_magazine {
    struct ceph_san_magazine *mag;  /* Current magazine for this CPU */
};

/* Global magazine pools */
struct ceph_san_batch {
    struct list_head full_magazines;   /* List of full magazines */
    struct list_head empty_magazines;  /* List of empty magazines */
    spinlock_t full_lock;             /* Protects full magazine list and count */
    spinlock_t empty_lock;            /* Protects empty magazine list and count */
    unsigned int nr_full;             /* Protected by full_lock */
    unsigned int nr_empty;            /* Protected by empty_lock */
    struct ceph_san_cpu_magazine __percpu *cpu_magazines; /* Per-CPU magazines */
    struct kmem_cache *magazine_cache; /* Cache for magazine allocations */
};

/* Initialize the batching system */
int ceph_san_batch_init(struct ceph_san_batch *batch);

/* Clean up the batching system */
void ceph_san_batch_cleanup(struct ceph_san_batch *batch);

/* Get an element from the batch */
void *ceph_san_batch_get(struct ceph_san_batch *batch);

/* Put an element back into the batch */
void ceph_san_batch_put(struct ceph_san_batch *batch, void *element);

#endif /* CEPH_SAN_BATCH_H */
