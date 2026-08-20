// SPDX-License-Identifier: GPL-2.0
/*
 * Per-CPU magazine batching for BLOG TLS context recycling.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include "blog_batch.h"
#include "blog.h"

static struct blog_magazine *alloc_magazine(struct blog_batch *batch, gfp_t gfp)
{
	struct blog_magazine *mag;

	mag = kmem_cache_zalloc(batch->magazine_cache, gfp);
	if (!mag)
		return NULL;

	INIT_LIST_HEAD(&mag->list);
	mag->count = 0;
	return mag;
}

static void free_magazine(struct blog_batch *batch, struct blog_magazine *mag)
{
	int i;
	struct blog_tls_pagefrag *composite;

	for (i = 0; i < mag->count; i++) {
		composite = mag->elements[i];
		if (composite)
			kvfree_atomic(composite);
	}

	kmem_cache_free(batch->magazine_cache, mag);
}

/**
 * blog_batch_init - Initialize the batching system
 * @batch: Batch structure to initialize
 * @mag_cache: Slab cache for magazine structs, or NULL to create one
 * @nr_prealloc: Number of composites to preallocate (0 = none)
 * @retain_limit: Max composites to retain on put; excess are freed (0 = unlimited)
 *
 * Pass nr_prealloc = 0 for batches that start empty (e.g. log_batch).
 */
int blog_batch_init(struct blog_batch *batch, struct kmem_cache *mag_cache,
		    unsigned int nr_prealloc, unsigned int retain_limit)
{
	unsigned int nr_mags, i, j;
	int cpu;
	struct blog_cpu_magazine *cpu_mag;
	struct blog_magazine *mag;
	struct blog_tls_pagefrag *composite;

	batch->nr_full = 0;
	batch->nr_empty = 0;
	batch->retain_limit = retain_limit;

	if (mag_cache) {
		batch->magazine_cache = mag_cache;
		batch->external_cache = true;
	} else {
		batch->magazine_cache = kmem_cache_create("blog_magazine",
						       sizeof(struct blog_magazine),
						       0, SLAB_HWCACHE_ALIGN, NULL);
		if (!batch->magazine_cache)
			return -ENOMEM;
		batch->external_cache = false;
	}

	INIT_LIST_HEAD(&batch->full_magazines);
	INIT_LIST_HEAD(&batch->empty_magazines);
	raw_spin_lock_init(&batch->full_lock);
	raw_spin_lock_init(&batch->empty_lock);

	batch->cpu_magazines = alloc_percpu(struct blog_cpu_magazine);
	if (!batch->cpu_magazines)
		goto cleanup_cache;

	for_each_possible_cpu(cpu) {
		cpu_mag = per_cpu_ptr(batch->cpu_magazines, cpu);
		cpu_mag->mag = NULL;
	}

	nr_mags = DIV_ROUND_UP(nr_prealloc, BLOG_MAGAZINE_SIZE);
	for (i = 0; i < nr_mags; i++) {
		mag = alloc_magazine(batch, GFP_KERNEL);
		if (!mag)
			goto cleanup;

		for (j = 0; j < BLOG_MAGAZINE_SIZE; j++) {
			composite = kvzalloc(BLOG_TLS_PAGEFRAG_ALLOC_SIZE,
					      GFP_KERNEL);
			if (!composite) {
				free_magazine(batch, mag);
				goto cleanup;
			}
			mag->elements[j] = composite;
			mag->count++;
		}

		raw_spin_lock(&batch->full_lock);
		list_add(&mag->list, &batch->full_magazines);
		batch->nr_full++;
		raw_spin_unlock(&batch->full_lock);
	}

	return 0;

cleanup:
	blog_batch_cleanup(batch);
	return -ENOMEM;

cleanup_cache:
	if (!batch->external_cache && batch->magazine_cache)
		kmem_cache_destroy(batch->magazine_cache);
	return -ENOMEM;
}

void blog_batch_cleanup(struct blog_batch *batch)
{
	int cpu;
	struct blog_magazine *mag, *tmp;
	struct blog_cpu_magazine *cpu_mag;

	if (batch->cpu_magazines) {
		for_each_possible_cpu(cpu) {
			cpu_mag = per_cpu_ptr(batch->cpu_magazines, cpu);
			if (cpu_mag->mag)
				free_magazine(batch, cpu_mag->mag);
		}
		free_percpu(batch->cpu_magazines);
	}

	raw_spin_lock(&batch->full_lock);
	list_for_each_entry_safe(mag, tmp, &batch->full_magazines, list) {
		list_del(&mag->list);
		batch->nr_full--;
		free_magazine(batch, mag);
	}
	raw_spin_unlock(&batch->full_lock);

	raw_spin_lock(&batch->empty_lock);
	list_for_each_entry_safe(mag, tmp, &batch->empty_magazines, list) {
		list_del(&mag->list);
		batch->nr_empty--;
		free_magazine(batch, mag);
	}
	raw_spin_unlock(&batch->empty_lock);

	if (!batch->external_cache && batch->magazine_cache)
		kmem_cache_destroy(batch->magazine_cache);

	batch->magazine_cache = NULL;
	batch->external_cache = false;
}

void *blog_batch_get(struct blog_batch *batch)
{
	struct blog_cpu_magazine *cpu_mag;
	struct blog_magazine *old_mag, *new_mag;
	void *element = NULL;

	preempt_disable();
	cpu_mag = this_cpu_ptr(batch->cpu_magazines);

	if (cpu_mag->mag && cpu_mag->mag->count > 0) {
		element = cpu_mag->mag->elements[--cpu_mag->mag->count];
		goto out;
	}

	old_mag = cpu_mag->mag;

	if (old_mag) {
		raw_spin_lock(&batch->empty_lock);
		list_add(&old_mag->list, &batch->empty_magazines);
		batch->nr_empty++;
		raw_spin_unlock(&batch->empty_lock);
		cpu_mag->mag = NULL;
	}

	if (READ_ONCE(batch->nr_full) > 0) {
		raw_spin_lock(&batch->full_lock);
		if (!list_empty(&batch->full_magazines)) {
			new_mag = list_first_entry(&batch->full_magazines,
						   struct blog_magazine, list);
			list_del(&new_mag->list);
			batch->nr_full--;
			raw_spin_unlock(&batch->full_lock);

			cpu_mag->mag = new_mag;
			if (new_mag->count > 0)
				element = new_mag->elements[--new_mag->count];
		} else {
			raw_spin_unlock(&batch->full_lock);
		}
	}
out:
	preempt_enable();
	return element;
}

bool blog_batch_put(struct blog_batch *batch, void *element)
{
	struct blog_cpu_magazine *cpu_mag;
	struct blog_magazine *mag;
	bool stored = true;

	/* Trim: if over retention limit, decline to store the element */
	if (batch->retain_limit &&
	    READ_ONCE(batch->nr_full) * BLOG_MAGAZINE_SIZE >= batch->retain_limit)
		return false;

	preempt_disable();
	cpu_mag = this_cpu_ptr(batch->cpu_magazines);

	if (likely(cpu_mag->mag && cpu_mag->mag->count < BLOG_MAGAZINE_SIZE)) {
		cpu_mag->mag->elements[cpu_mag->mag->count++] = element;
		goto out;
	}

	if (likely(cpu_mag->mag && cpu_mag->mag->count >= BLOG_MAGAZINE_SIZE)) {
		raw_spin_lock(&batch->full_lock);
		list_add_tail(&cpu_mag->mag->list, &batch->full_magazines);
		batch->nr_full++;
		raw_spin_unlock(&batch->full_lock);
		cpu_mag->mag = NULL;
	}

	if (likely(!cpu_mag->mag)) {
		raw_spin_lock(&batch->empty_lock);
		if (!list_empty(&batch->empty_magazines)) {
			mag = list_first_entry(&batch->empty_magazines,
					       struct blog_magazine, list);
			list_del(&mag->list);
			batch->nr_empty--;
			raw_spin_unlock(&batch->empty_lock);
			cpu_mag->mag = mag;
		} else {
			raw_spin_unlock(&batch->empty_lock);
			cpu_mag->mag = alloc_magazine(batch, GFP_ATOMIC);
		}

		if (unlikely(!cpu_mag->mag)) {
			stored = false;
			goto out;
		}
	}
	cpu_mag->mag->elements[cpu_mag->mag->count++] = element;
out:
	preempt_enable();
	return stored;
}
