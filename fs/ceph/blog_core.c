// SPDX-License-Identifier: GPL-2.0
/*
 * BLOG logger: source-ID registry and log iteration.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/time.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/hash.h>

#include <linux/rhashtable.h>
#include "blog.h"
#include "blog_batch.h"
#include "blog_pagefrag.h"
#include "blog_ser.h"
#include "blog_des.h"
#include "blog_module.h"

static bool blog_source_matches(const struct blog_source_info *info,
				const char *file, const char *func,
				unsigned int line, const char *fmt)
{
	return info->file && info->func && info->fmt &&
	       info->line == line && info->fmt == fmt &&
	       !strcmp(info->file, file) && !strcmp(info->func, func);
}

static u32 blog_source_hash(const char *fmt, unsigned int line, u32 mask)
{
	return (hash_ptr((void *)fmt, 32) ^ line) & mask;
}

/**
 * blog_get_source_id - Get or create a source ID for the given location
 * @logger: Logger instance to use
 * @file: Source file name
 * @func: Function name
 * @line: Line number
 * @fmt: Format string
 */
u32 blog_get_source_id(struct blog_logger *logger, const char *file,
		       const char *func, unsigned int line, const char *fmt)
{
	struct blog_source_info *info;
	u32 id, slot, first;

	if (!logger || !logger->source_hash)
		return 0;

	spin_lock(&logger->source_lock);
	slot = blog_source_hash(fmt, line, logger->source_hash_mask);
	first = slot;
	do {
		id = logger->source_hash[slot];
		if (!id)
			break;
		info = &logger->source_map[id];
		if (blog_source_matches(info, file, func, line, fmt))
			goto out_unlock;
		slot = (slot + 1) & logger->source_hash_mask;
	} while (slot != first);

	id = logger->next_source_id;
	if (id >= logger->max_source_ids) {
		spin_unlock(&logger->source_lock);
		pr_warn_once("blog: source ID overflow\n");
		return 0;
	}

	/* No empty slot in the hash table. */
	if (logger->source_hash[slot]) {
		spin_unlock(&logger->source_lock);
		pr_warn_once("blog: source hash full\n");
		return 0;
	}

	logger->next_source_id = id + 1;
	info = &logger->source_map[id];
	info->file = file;
	info->func = func;
	info->line = line;
	info->fmt = fmt;
	info->warn_count = 0;
	logger->source_hash[slot] = id;

out_unlock:
	spin_unlock(&logger->source_lock);
	return id;
}

u32 blog_get_source_id_cached(struct blog_logger *logger,
			      struct blog_source_id_cache *cache,
			      const char *file, const char *func,
			      unsigned int line, const char *fmt)
{
	struct blog_logger *cached_logger;
	u64 generation;
	unsigned int seq;
	u32 sid;

	if (!logger)
		return 0;
	if (!cache)
		return blog_get_source_id(logger, file, func, line, fmt);

	/* Callsites are shared by mounts, so read one lockless snapshot. */
	do {
		seq = read_seqcount_begin(&cache->seq);
		sid = cache->id;
		cached_logger = cache->logger;
		generation = cache->generation;
	} while (read_seqcount_retry(&cache->seq, seq));
	if (sid && cached_logger == logger &&
	    generation == logger->generation)
		return sid;

	spin_lock(&cache->lock);
	sid = cache->id;
	if (sid && cache->logger == logger &&
	    cache->generation == logger->generation)
		goto out;

	sid = blog_get_source_id(logger, file, func, line, fmt);
	if (sid) {
		write_seqcount_begin(&cache->seq);
		cache->logger = logger;
		cache->generation = logger->generation;
		cache->id = sid;
		write_seqcount_end(&cache->seq);
	}

out:
	spin_unlock(&cache->lock);
	return sid;
}

struct blog_source_info *blog_get_source_info(struct blog_logger *logger, u32 id)
{
	if (!logger || unlikely(id == 0 || id >= logger->max_source_ids))
		return NULL;
	return &logger->source_map[id];
}

void blog_log_iter_init(struct blog_log_iter *iter, struct blog_pagefrag *pf,
			u64 head_snapshot)
{
	if (!iter || !pf)
		return;

	iter->pf = pf;
	iter->current_offset = 0;
	iter->end_offset = head_snapshot;
	iter->prev_offset = 0;
	iter->steps = 0;
}

struct blog_log_entry *blog_log_iter_next(struct blog_log_iter *iter)
{
	struct blog_log_entry *entry;

	if (!iter || iter->current_offset >= iter->end_offset)
		return NULL;

	/* Ensure the entry header itself fits within the snapshot. */
	if (iter->current_offset + sizeof(struct blog_log_entry) >
	    iter->end_offset)
		return NULL;

	entry = blog_pagefrag_get_ptr(iter->pf, iter->current_offset);
	if (!entry)
		return NULL;

	/* Reject truncated / corrupt payloads before deserializing. */
	if (iter->current_offset + sizeof(*entry) + entry->len >
	    iter->end_offset)
		return NULL;

	iter->prev_offset = iter->current_offset;
	iter->current_offset +=
		round_up(sizeof(struct blog_log_entry) + entry->len, 8);
	iter->steps++;

	/*
	 * Clamp to the snapshot boundary: a corrupted entry->len could
	 * push current_offset past end_offset into garbage memory.
	 */
	if (iter->current_offset > iter->end_offset)
		iter->current_offset = iter->end_offset;

	return entry;
}

int blog_des_entry(struct blog_logger *logger, struct blog_log_entry *entry,
		   char *output, size_t out_size, blog_client_des_fn client_cb)
{
	int len = 0;
	struct blog_source_info *source;

	if (!entry || !output)
		return -EINVAL;

	if (client_cb) {
		len = client_cb(output, out_size, entry->client_id);
		if (len < 0)
			return len;
		if (len >= out_size)
			return len;
	}

	source = blog_get_source_info(logger, entry->source_id);
	if (!source) {
		len += scnprintf(output + len, out_size - len,
				 "[unknown source %u]", entry->source_id);
		return len;
	}

	/* Snapshot under source_lock (same pattern as blog_sources_show). */
	{
		const char *file, *func, *fmt;
		unsigned int line;
		int ret;

		spin_lock(&logger->source_lock);
		file = source->file;
		func = source->func;
		line = source->line;
		fmt = source->fmt;
		spin_unlock(&logger->source_lock);
		if (!file) {
			len += scnprintf(output + len, out_size - len,
					 "[unknown source %u]",
					 entry->source_id);
			return len;
		}

		len += scnprintf(output + len, out_size - len, "[%s:%s:%u] ",
				 file, func, line);
		if (len >= out_size)
			return len;

		ret = blog_des_reconstruct(fmt, entry->buffer, entry->len,
					   output + len, out_size - len);
		if (ret < 0)
			return ret;
		len += ret;
	}

	return len;
}
