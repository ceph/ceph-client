// SPDX-License-Identifier: GPL-2.0
/*
 * Ceph BLOG debugfs.
 */

#include <linux/ceph/ceph_debug.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/timekeeping.h>
#include <linux/ceph/ceph_blog.h>
#include "blog.h"
#include "blog_des.h"
#include "blog_module.h"

#include "super.h"

static int jiffies_to_formatted_time(u64 jiffies_value, char *buffer,
	size_t buffer_len);

struct blog_dbg_file {
	struct ceph_fs_client *fsc;
	struct blog_module_context *ctx;
};

static int blog_dbg_pin(struct ceph_fs_client *fsc,
			struct blog_dbg_file *priv)
{
	struct blog_module_context *ctx;

	if (!fsc)
		return -ENODEV;

	/*
	 * Module + blog_ctx refs only.  No open-count wait on fsc:
	 * debugfs_create_file() already get/puts around read/write, so
	 * remove waits for in-flight ops; release must not touch fsc.
	 */
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	rcu_read_lock();
	ctx = rcu_dereference(fsc->blog_ctx);
	if (ctx && !refcount_inc_not_zero(&ctx->refcount))
		ctx = NULL;
	rcu_read_unlock();

	priv->fsc = fsc;
	priv->ctx = ctx;
	return 0;
}

static void blog_dbg_unpin(struct blog_dbg_file *priv)
{
	if (priv->ctx)
		blog_module_put(priv->ctx);
	module_put(THIS_MODULE);
}

static struct blog_logger *blog_dbg_logger(struct blog_dbg_file *priv)
{
	if (!priv || !priv->ctx)
		return NULL;
	return READ_ONCE(priv->ctx->logger);
}

/**
 * blog_entries_show - dump decoded records
 *
 * ID-cursor walk: each pass finds the next context by ascending ID, drops
 * logger->lock, and snapshots only its published bytes under pf->lock.
 * snapshot_mutex keeps retained contexts from being reclaimed between the
 * list lookup and the snapshot.
 */
static int blog_entries_show(struct seq_file *s, void *p)
{
	struct blog_dbg_file *priv = s->private;
	struct blog_logger *logger;
	struct blog_tls_ctx *ctx;
	void *buf_copy;
	char *output_buf;
	int entry_count = 0;
	u64 cursor_id = 0;

	logger = blog_dbg_logger(priv);
	if (!logger) {
		seq_puts(s, "Ceph BLOG context not initialized\n");
		return 0;
	}

	buf_copy = kmalloc(BLOG_TLS_PAGEFRAG_BUFFER_SIZE, GFP_KERNEL);
	if (!buf_copy)
		return -ENOMEM;
	/* Match live buffer capacity so long reconstructed lines are not cut. */
	output_buf = kmalloc(BLOG_TLS_PAGEFRAG_BUFFER_SIZE, GFP_KERNEL);
	if (!output_buf) {
		kfree(buf_copy);
		return -ENOMEM;
	}

	for (;;) {
		struct blog_tls_ctx *best = NULL;
		struct blog_pagefrag *pf;
		unsigned long base_jiffies;
		struct blog_pagefrag tmp_pf;
		struct blog_log_iter iter;
		struct blog_log_entry *entry;
		u64 best_id = U64_MAX;
		u64 head;
		int ret;

		mutex_lock(&logger->snapshot_mutex);
		spin_lock(&logger->lock);
		list_for_each_entry(ctx, &logger->contexts, list) {
			if (ctx->id > cursor_id && ctx->id < best_id) {
				best = ctx;
				best_id = ctx->id;
			}
		}

		if (!best) {
			spin_unlock(&logger->lock);
			mutex_unlock(&logger->snapshot_mutex);
			break;
		}

		pf = blog_ctx_pf(best);
		/* Idle contexts lagging a clear look empty immediately. */
		if (atomic64_read(&best->clear_seq) !=
		    atomic64_read(&logger->clear_seq)) {
			spin_unlock(&logger->lock);
			cursor_id = best_id;
			mutex_unlock(&logger->snapshot_mutex);
			continue;
		}
		spin_unlock(&logger->lock);

		/*
		 * Snapshot published prefix under pf->lock.  Buffer is SZ_4K,
		 * so holding the lock across the copy is cheaper and safer
		 * than an unbounded head/head2 retry loop.
		 */
		spin_lock(&pf->lock);
		head = smp_load_acquire(&pf->head);
		base_jiffies = READ_ONCE(best->base_jiffies);
		if (head)
			memcpy(buf_copy, pf->buffer, head);
		spin_unlock(&pf->lock);

		/*
		 * Rotate publishes the snapshot (id swap + contexts insert)
		 * before clearing live and without snapshot_mutex.  After
		 * we dropped logger->lock it can move best_id onto a
		 * snapshot and give this ctx a new id.  Any id mismatch
		 * means this copy is not the retired window; leave the
		 * cursor so the next walk finds the snapshot.  Do not
		 * advance just because head is non-zero. That may be
		 * the *new* live tail.
		 */
		spin_lock(&logger->lock);
		if (best->id != best_id) {
			spin_unlock(&logger->lock);
			mutex_unlock(&logger->snapshot_mutex);
			continue;
		}
		cursor_id = best_id;
		spin_unlock(&logger->lock);
		mutex_unlock(&logger->snapshot_mutex);

		if (!head)
			continue;

		/* Deserialize and output outside any lock */
		memset(&tmp_pf, 0, sizeof(tmp_pf));
		tmp_pf.buffer = buf_copy;
		tmp_pf.capacity = head;
		tmp_pf.head = head;

		blog_log_iter_init(&iter, &tmp_pf, head);

		while ((entry = blog_log_iter_next(&iter)) != NULL) {
			char time_buf[64];
			u64 entry_jiffies;

			entry_count++;
			memset(output_buf, 0, BLOG_TLS_PAGEFRAG_BUFFER_SIZE);
			ret = blog_des_entry(logger, entry,
					     output_buf,
					     BLOG_TLS_PAGEFRAG_BUFFER_SIZE,
					     ceph_blog_client_des_callback);
			if (ret < 0) {
				seq_printf(s,
					   "[Error deserializing entry %d: %d]\n",
					   entry_count, ret);
				continue;
			}
			entry_jiffies = base_jiffies + entry->ts_delta;
			if (jiffies_to_formatted_time(entry_jiffies, time_buf,
						      sizeof(time_buf)) < 0)
				strscpy(time_buf, "(invalid)", sizeof(time_buf));
			if (ret > 0 && output_buf[ret - 1] == '\n')
				output_buf[ret - 1] = '\0';
			seq_printf(s, "%s %s\n", time_buf, output_buf);
		}
	}

	kfree(output_buf);
	kfree(buf_copy);
	return 0;
}

static int blog_entries_open(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = blog_dbg_pin(inode->i_private, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	ret = single_open(file, blog_entries_show, priv);
	if (ret) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return ret;
}

static int blog_dbg_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct blog_dbg_file *priv = seq ? seq->private : NULL;
	int ret = single_release(inode, file);

	if (priv) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return ret;
}

static const struct file_operations blog_entries_fops = {
	.owner = THIS_MODULE,
	.open = blog_entries_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = blog_dbg_release,
};

static int blog_stats_show(struct seq_file *s, void *p)
{
	struct blog_dbg_file *priv = s->private;
	struct blog_logger *logger = blog_dbg_logger(priv);

	seq_puts(s, "Ceph BLOG Statistics\n");
	seq_puts(s, "====================\n\n");

	if (!logger) {
		seq_puts(s, "Ceph BLOG context not initialized\n");
		return 0;
	}

	seq_puts(s, "Ceph Module Logger State:\n");
	seq_printf(s, "  Total contexts allocated: %lu\n",
		   logger->total_contexts_allocated);
	seq_printf(s, "  Next context ID: %llu\n",
		   READ_ONCE(logger->next_ctx_id));
	seq_printf(s, "  Next source ID: %u\n",
		   READ_ONCE(logger->next_source_id));

	seq_puts(s, "\nAllocation Batch:\n");
	seq_printf(s, "  Full magazines: %u\n",
		   READ_ONCE(logger->alloc_batch.nr_full));
	seq_printf(s, "  Empty magazines: %u\n",
		   READ_ONCE(logger->alloc_batch.nr_empty));

	seq_puts(s, "\nLog Batch:\n");
	seq_printf(s, "  Full magazines: %u\n",
		   READ_ONCE(logger->log_batch.nr_full));
	seq_printf(s, "  Empty magazines: %u\n",
		   READ_ONCE(logger->log_batch.nr_empty));

	return 0;
}

static int blog_stats_open(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = blog_dbg_pin(inode->i_private, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	ret = single_open(file, blog_stats_show, priv);
	if (ret) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return ret;
}

static const struct file_operations blog_stats_fops = {
	.owner = THIS_MODULE,
	.open = blog_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = blog_dbg_release,
};

static int blog_sources_show(struct seq_file *s, void *p)
{
	struct blog_dbg_file *priv = s->private;
	struct blog_logger *logger = blog_dbg_logger(priv);
	struct blog_source_info *source;
	const char *file, *func, *fmt;
	unsigned int line;
	int warn_count;
	u32 id;
	int count = 0;

	seq_puts(s, "Ceph BLOG Source Locations\n");
	seq_puts(s, "===========================\n\n");

	if (!logger) {
		seq_puts(s, "Ceph BLOG context not initialized\n");
		return 0;
	}

	for (id = 1; id < logger->max_source_ids; id++) {
		source = blog_get_source_info(logger, id);
		if (!source)
			continue;

		spin_lock(&logger->source_lock);
		file = source->file;
		func = source->func;
		line = source->line;
		fmt = source->fmt;
		warn_count = source->warn_count;
		spin_unlock(&logger->source_lock);
		if (!file)
			continue;

		count++;
		seq_printf(s, "ID %u: %s:%s:%u\n", id, file, func, line);
		seq_printf(s, "  Format: %s\n", fmt ? fmt : "(null)");
		seq_printf(s, "  Warnings: %d\n", warn_count);

		seq_puts(s, "\n");
	}

	seq_printf(s, "Total registered sources: %d\n", count);

	return 0;
}

static int blog_sources_open(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = blog_dbg_pin(inode->i_private, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	ret = single_open(file, blog_sources_show, priv);
	if (ret) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return ret;
}

static const struct file_operations blog_sources_fops = {
	.owner = THIS_MODULE,
	.open = blog_sources_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = blog_dbg_release,
};

static int blog_clients_show(struct seq_file *s, void *p)
{
	struct blog_dbg_file *priv = s->private;
	struct ceph_fs_client *fsc = priv->fsc;
	struct ceph_client *client;
	u32 client_id;

	seq_puts(s, "Ceph BLOG Mount Client\n");
	seq_puts(s, "======================\n\n");

	if (!fsc || !fsc->client) {
		seq_puts(s, "client unavailable\n");
		return 0;
	}

	client = fsc->client;
	client_id = READ_ONCE(client->blog_client_id);

	seq_printf(s, "FSID: %pU\n", &client->fsid);
	if (client->monc.auth)
		seq_printf(s, "Global ID: %llu\n", client->monc.auth->global_id);
	else
		seq_puts(s, "Global ID: (unavailable)\n");
	if (client_id)
		seq_printf(s, "Cached BLOG client ID: %u\n", client_id);
	else
		seq_puts(s, "Cached BLOG client ID: (unassigned)\n");
	if (ceph_blog_is_enabled(fsc))
		seq_puts(s, "BLOG enabled: yes\n");
	else
		seq_puts(s, "BLOG enabled: no\n");

	return 0;
}

static int blog_clients_open(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = blog_dbg_pin(inode->i_private, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	ret = single_open(file, blog_clients_show, priv);
	if (ret) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return ret;
}

static const struct file_operations blog_clients_fops = {
	.owner = THIS_MODULE,
	.open = blog_clients_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = blog_dbg_release,
};

static ssize_t blog_clear_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct blog_dbg_file *priv = file->private_data;
	struct blog_logger *logger = blog_dbg_logger(priv);
	char cmd[16];

	if (count >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;

	cmd[count] = '\0';

	/* Only accept exact "clear" (optional trailing newline) */
	if (strncmp(cmd, "clear", 5) != 0 ||
	    (cmd[5] != '\0' && cmd[5] != '\n'))
		return -EINVAL;

	/*
	 * Bump clear_seq so readers treat lagging contexts as empty until
	 * their next write resets the pagefrag.  Also set NEEDS_RESET so a
	 * concurrent writer notices promptly.  Hold snapshot_mutex so a
	 * concurrent entries snapshot cannot copy pre-clear data after
	 * this write returns.
	 */
	if (logger) {
		struct blog_tls_ctx *tls_ctx;

		mutex_lock(&logger->snapshot_mutex);
		spin_lock(&logger->lock);
		atomic64_inc(&logger->clear_seq);
		list_for_each_entry(tls_ctx, &logger->contexts, list)
			set_bit(BLOG_CTX_NEEDS_RESET, &tls_ctx->flags);
		spin_unlock(&logger->lock);
		mutex_unlock(&logger->snapshot_mutex);
		pr_debug("ceph: BLOG entries cleared via debugfs\n");
	}

	return count;
}

static int blog_clear_open(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = blog_dbg_pin(inode->i_private, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	file->private_data = priv;
	return 0;
}

static int blog_clear_release(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv = file->private_data;

	if (priv) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return 0;
}

static const struct file_operations blog_clear_fops = {
	.owner = THIS_MODULE,
	.open = blog_clear_open,
	.write = blog_clear_write,
	.release = blog_clear_release,
	.llseek = noop_llseek,
};

static ssize_t blog_enabled_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct blog_dbg_file *priv = file->private_data;
	char tmp[32];
	int len;

	len = scnprintf(tmp, sizeof(tmp), "%llu\n",
			(u64)READ_ONCE(priv->fsc->blog_enabled));
	return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static ssize_t blog_enabled_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct blog_dbg_file *priv = file->private_data;
	u64 val;
	int ret;

	ret = kstrtoull_from_user(buf, count, 0, &val);
	if (ret)
		return ret;
	if (val > 1)
		return -EINVAL;

	ret = ceph_blog_set_enabled(priv->fsc, val);
	return ret ? ret : count;
}

static int blog_enabled_open(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv;
	int ret;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = blog_dbg_pin(inode->i_private, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	file->private_data = priv;
	return 0;
}

static int blog_enabled_release(struct inode *inode, struct file *file)
{
	struct blog_dbg_file *priv = file->private_data;

	if (priv) {
		blog_dbg_unpin(priv);
		kfree(priv);
	}
	return 0;
}

static const struct file_operations blog_enabled_fops = {
	.owner = THIS_MODULE,
	.open = blog_enabled_open,
	.release = blog_enabled_release,
	.read = blog_enabled_read,
	.write = blog_enabled_write,
	.llseek = generic_file_llseek,
};

int ceph_blog_debugfs_init(struct ceph_fs_client *fsc)
{
	struct dentry *dir;

	if (!fsc || !fsc->client || !fsc->client->debugfs_dir)
		return -EINVAL;
	if (fsc->debugfs_blog)
		return 0;

	dir = debugfs_create_dir("blog", fsc->client->debugfs_dir);
	if (IS_ERR(dir))
		return PTR_ERR(dir);
	fsc->debugfs_blog = dir;

	debugfs_create_file("enabled", 0600, fsc->debugfs_blog, fsc,
			    &blog_enabled_fops);
	debugfs_create_file("entries", 0444, fsc->debugfs_blog, fsc,
			    &blog_entries_fops);

	debugfs_create_file("stats", 0444, fsc->debugfs_blog, fsc,
			    &blog_stats_fops);

	debugfs_create_file("sources", 0444, fsc->debugfs_blog, fsc,
			    &blog_sources_fops);

	debugfs_create_file("clients", 0444, fsc->debugfs_blog, fsc,
			    &blog_clients_fops);

	debugfs_create_file("clear", 0200, fsc->debugfs_blog, fsc,
			    &blog_clear_fops);

	pr_debug("ceph: BLOG debugfs initialized\n");
	return 0;
}

void ceph_blog_debugfs_cleanup(struct ceph_fs_client *fsc)
{
	if (!fsc || !fsc->debugfs_blog)
		return;

	debugfs_remove_recursive(fsc->debugfs_blog);
	fsc->debugfs_blog = NULL;
	pr_debug("ceph: BLOG debugfs cleaned up\n");
}

static int jiffies_to_formatted_time(u64 jiffies_value, char *buffer,
	size_t buffer_len)
{
	u64 now_ns = ktime_get_real_ns();
	u64 now_jiffies = get_jiffies_64();
	u64 delta_jiffies = (now_jiffies > jiffies_value) ?
		now_jiffies - jiffies_value : 0;
	u64 delta_ns = jiffies64_to_nsecs(delta_jiffies);
	u64 event_ns = (delta_ns > now_ns) ? 0 : now_ns - delta_ns;
	struct timespec64 event_ts = ns_to_timespec64(event_ns);
	struct tm tm_time;

	if (!buffer || !buffer_len)
		return -EINVAL;

	time64_to_tm(event_ts.tv_sec, 0, &tm_time);

	return scnprintf(buffer, buffer_len,
			"%04ld-%02d-%02d %02d:%02d:%02d.%03lu",
			tm_time.tm_year + 1900, tm_time.tm_mon + 1, tm_time.tm_mday,
			tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec,
			(unsigned long)(event_ts.tv_nsec / NSEC_PER_MSEC));
}
