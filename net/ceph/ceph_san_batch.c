#include <linux/slab.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/ceph/ceph_san_batch.h>

/* Number of magazines to preallocate during initialization */
#define CEPH_SAN_INIT_MAGAZINES 4

static struct ceph_san_magazine *alloc_magazine(struct ceph_san_batch *batch, bool fill)
{
    struct ceph_san_magazine *mag;
    int i;

    mag = kmem_cache_alloc(batch->magazine_cache, GFP_KERNEL);
    if (!mag)
        return NULL;

    INIT_LIST_HEAD(&mag->list);
    mag->count = 0;

    /* Pre-fill magazine if requested and allocation function exists */
    if (fill && batch->alloc_element) {
        for (i = 0; i < CEPH_SAN_MAGAZINE_SIZE; i++) {
            void *element = batch->alloc_element();
            if (!element) {
                /* Clean up already allocated elements on failure */
                while (mag->count > 0)
                    batch->free_element(mag->elements[--mag->count]);
                kmem_cache_free(batch->magazine_cache, mag);
                return NULL;
            }
            mag->elements[mag->count++] = element;
        }
    }
    return mag;
}

static void free_magazine(struct ceph_san_batch *batch, struct ceph_san_magazine *mag)
{
    /* Free all elements in the magazine */
    while (mag->count > 0)
        batch->free_element(mag->elements[--mag->count]);
    kmem_cache_free(batch->magazine_cache, mag);
}

/**
 * ceph_san_batch_init - Initialize the batching system
 * @batch: Batch structure to initialize
 * @alloc_element: Function to allocate new elements
 * @free_element: Function to free elements
 *
 * Allocates and initializes the per-CPU magazines and global pools.
 *
 * Return: 0 on success, negative error code on failure
 */
int ceph_san_batch_init(struct ceph_san_batch *batch,
                       void *(*alloc_element)(void),
                       void (*free_element)(void *))
{
    int cpu, i;
    struct ceph_san_cpu_magazine *cpu_mag;
    struct ceph_san_magazine *mag;

    if (!alloc_element || !free_element)
        return -EINVAL;

    /* Store allocation and free functions */
    batch->alloc_element = alloc_element;
    batch->free_element = free_element;

    /* Initialize counters */
    batch->nr_full = 0;
    batch->nr_empty = 0;

    /* Create magazine cache */
    batch->magazine_cache = kmem_cache_create("ceph_san_magazine",
                                            sizeof(struct ceph_san_magazine),
                                            0, SLAB_HWCACHE_ALIGN, NULL);
    if (!batch->magazine_cache)
        return -ENOMEM;

    /* Initialize global magazine lists */
    INIT_LIST_HEAD(&batch->full_magazines);
    INIT_LIST_HEAD(&batch->empty_magazines);
    spin_lock_init(&batch->full_lock);
    spin_lock_init(&batch->empty_lock);

    /* Allocate per-CPU magazines */
    batch->cpu_magazines = alloc_percpu(struct ceph_san_cpu_magazine);
    if (!batch->cpu_magazines)
        goto cleanup_cache;

    /* Initialize per-CPU magazines */
    for_each_possible_cpu(cpu) {
        cpu_mag = per_cpu_ptr(batch->cpu_magazines, cpu);
        cpu_mag->mag = NULL;
    }

    /* Pre-allocate some magazines - half empty, half full */
    for (i = 0; i < CEPH_SAN_INIT_MAGAZINES; i++) {
        /* Alternate between empty and full magazines */
        mag = alloc_magazine(batch, i & 1);
        if (!mag)
            goto cleanup;

        if (i & 1) {
            /* Add full magazine to full pool */
            spin_lock(&batch->full_lock);
            list_add(&mag->list, &batch->full_magazines);
            batch->nr_full++;
            spin_unlock(&batch->full_lock);
        } else {
            /* Add empty magazine to empty pool */
            spin_lock(&batch->empty_lock);
            list_add(&mag->list, &batch->empty_magazines);
            batch->nr_empty++;
            spin_unlock(&batch->empty_lock);
        }
    }

    return 0;

cleanup:
    ceph_san_batch_cleanup(batch);
    return -ENOMEM;

cleanup_cache:
    kmem_cache_destroy(batch->magazine_cache);
    return -ENOMEM;
}
EXPORT_SYMBOL(ceph_san_batch_init);

/**
 * ceph_san_batch_cleanup - Clean up the batching system
 * @batch: Batch structure to clean up
 */
void ceph_san_batch_cleanup(struct ceph_san_batch *batch)
{
    int cpu;
    struct ceph_san_magazine *mag, *tmp;
    struct ceph_san_cpu_magazine *cpu_mag;

    /* Free per-CPU magazines */
    if (batch->cpu_magazines) {
        for_each_possible_cpu(cpu) {
            cpu_mag = per_cpu_ptr(batch->cpu_magazines, cpu);
            if (cpu_mag->mag)
                free_magazine(batch, cpu_mag->mag);
        }
        free_percpu(batch->cpu_magazines);
    }

    /* Free magazines in the full pool */
    spin_lock(&batch->full_lock);
    list_for_each_entry_safe(mag, tmp, &batch->full_magazines, list) {
        list_del(&mag->list);
        batch->nr_full--;
        free_magazine(batch, mag);
    }
    spin_unlock(&batch->full_lock);

    /* Free magazines in the empty pool */
    spin_lock(&batch->empty_lock);
    list_for_each_entry_safe(mag, tmp, &batch->empty_magazines, list) {
        list_del(&mag->list);
        batch->nr_empty--;
        free_magazine(batch, mag);
    }
    spin_unlock(&batch->empty_lock);

    /* Destroy magazine cache */
    if (batch->magazine_cache)
        kmem_cache_destroy(batch->magazine_cache);
}
EXPORT_SYMBOL(ceph_san_batch_cleanup);

/**
 * ceph_san_batch_get - Get an element from the batch
 * @batch: Batch to get element from
 *
 * Return: Element from the magazine, or NULL if none available
 */
void *ceph_san_batch_get(struct ceph_san_batch *batch)
{
    struct ceph_san_cpu_magazine *cpu_mag;
    struct ceph_san_magazine *old_mag, *new_mag;
    void *element = NULL;

    cpu_mag = this_cpu_ptr(batch->cpu_magazines);

    /* If we have a magazine and it has elements, use it */
    if (cpu_mag->mag && cpu_mag->mag->count > 0) {
        element = cpu_mag->mag->elements[--cpu_mag->mag->count];
        return element;
    }

    /* Current magazine is empty, try to get a full one */
    old_mag = cpu_mag->mag;

    /* Return old magazine to empty pool if we have one */
    if (old_mag) {
        spin_lock(&batch->empty_lock);
        list_add(&old_mag->list, &batch->empty_magazines);
        batch->nr_empty++;
        spin_unlock(&batch->empty_lock);
        cpu_mag->mag = NULL;
    }

    /* Try to get a full magazine first */
    spin_lock(&batch->full_lock);
    if (!list_empty(&batch->full_magazines)) {
        new_mag = list_first_entry(&batch->full_magazines,
                                 struct ceph_san_magazine, list);
        list_del(&new_mag->list);
        batch->nr_full--;
        spin_unlock(&batch->full_lock);

        cpu_mag->mag = new_mag;
        element = new_mag->elements[--new_mag->count];
    } else {
        spin_unlock(&batch->full_lock);
        /* No full magazine available, create and fill a new one */
        new_mag = alloc_magazine(batch, true);
        if (new_mag && new_mag->count > 0) {
            cpu_mag->mag = new_mag;
            element = new_mag->elements[--new_mag->count];
        } else if (new_mag) {
            /* Magazine allocated but couldn't be filled */
            spin_lock(&batch->empty_lock);
            list_add(&new_mag->list, &batch->empty_magazines);
            batch->nr_empty++;
            spin_unlock(&batch->empty_lock);
        }
    }

    return element;
}
EXPORT_SYMBOL(ceph_san_batch_get);

/**
 * ceph_san_batch_put - Put an element back into the batch
 * @batch: Batch to put element into
 * @element: Element to put back
 */
 //TOOD this shit needs a rewrite
void ceph_san_batch_put(struct ceph_san_batch *batch, void *element)
{
    struct ceph_san_cpu_magazine *cpu_mag;
    struct ceph_san_magazine *old_mag, *new_mag;

    cpu_mag = this_cpu_ptr(batch->cpu_magazines);

    /* If we don't have a magazine, get an empty one */
    if (!cpu_mag->mag) {
        spin_lock(&batch->empty_lock);
        if (!list_empty(&batch->empty_magazines)) {
            cpu_mag->mag = list_first_entry(&batch->empty_magazines,
                                          struct ceph_san_magazine, list);
            list_del(&cpu_mag->mag->list);
            batch->nr_empty--;
            spin_unlock(&batch->empty_lock);
        } else {
            spin_unlock(&batch->empty_lock);
            /* No empty magazine available, allocate a new one */
            cpu_mag->mag = alloc_magazine(batch, false);
        }

        if (!cpu_mag->mag) {
            /* If we can't get a magazine, free the element */
            pr_err("Failed to allocate magazine for batch put\n");
            batch->free_element(element);
            return;
        }
    }

    /* If current magazine isn't full, add to it */
    if (cpu_mag->mag->count < CEPH_SAN_MAGAZINE_SIZE) {
        cpu_mag->mag->elements[cpu_mag->mag->count++] = element;
        return;
    }

    /* Current magazine is full, move it to the full pool */
    old_mag = cpu_mag->mag;

    /* Try to get an empty magazine */
    spin_lock(&batch->empty_lock);
    if (!list_empty(&batch->empty_magazines)) {
        new_mag = list_first_entry(&batch->empty_magazines,
                                 struct ceph_san_magazine, list);
        list_del(&new_mag->list);
        batch->nr_empty--;
        spin_unlock(&batch->empty_lock);
    } else {
        spin_unlock(&batch->empty_lock);
        new_mag = alloc_magazine(batch, false);
    }

    if (new_mag) {
        /* Move full magazine to full pool */
        spin_lock(&batch->full_lock);
        list_add(&old_mag->list, &batch->full_magazines);
        batch->nr_full++;
        spin_unlock(&batch->full_lock);

        /* Use new magazine */
        cpu_mag->mag = new_mag;
        new_mag->elements[new_mag->count++] = element;
    } else {
        /* Failed to get new magazine, free the element */
        batch->free_element(element);
    }
}
EXPORT_SYMBOL(ceph_san_batch_put);
