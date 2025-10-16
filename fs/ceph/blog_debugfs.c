// SPDX-License-Identifier: GPL-2.0
/*
 * Ceph BLOG debugfs interface
 *
 * Provides debugfs entries to view and manage BLOG entries for Ceph
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/timekeeping.h>
#include <linux/ceph/ceph_debug.h>
#include <linux/ceph/ceph_blog.h>
#include <linux/blog/blog.h>
#include <linux/blog/blog_des.h>

static struct dentry *ceph_blog_debugfs_dir;

static int jiffies_to_formatted_time(u64 jiffies_value, char *buffer,
	size_t buffer_len);

/**
 * blog_entries_show - Show all BLOG entries for Ceph
 *
 * Iterates through all contexts and their pagefrags, deserializing entries
 * using BLOG's deserialization with Ceph's client callback
 */
static int blog_entries_show(struct seq_file *s, void *p)
{
	struct blog_tls_ctx *ctx;
	struct blog_log_iter iter;
	struct blog_log_entry *entry;
	char output_buf[1024];
	int ret;
	int entry_count = 0;
	int ctx_count = 0;

	seq_printf(s, "Ceph BLOG Entries\n");
	seq_printf(s, "=================\n\n");

	/* Access the Ceph module's logger contexts */
	if (!ceph_blog_ctx || !ceph_blog_ctx->logger) {
		seq_printf(s, "Ceph BLOG context not initialized\n");
		return 0;
	}

	spin_lock(&ceph_blog_ctx->logger->lock);

	list_for_each_entry(ctx, &ceph_blog_ctx->logger->contexts, list) {
		ctx_count++;
		seq_printf(s, "Context %d (ID: %llu, PID: %d, Comm: %s)\n",
		          ctx_count, ctx->id, ctx->pid, ctx->comm);
		seq_printf(s, "  Base jiffies: %lu, Refcount: %d\n",
		          ctx->base_jiffies, atomic_read(&ctx->refcount));

		/* Initialize iterator for this context's pagefrag */
		blog_log_iter_init(&iter, &ctx->pf);

		/* Iterate through all entries in this context */
		while ((entry = blog_log_iter_next(&iter)) != NULL) {
			entry_count++;

			/* Clear output buffer */
			memset(output_buf, 0, sizeof(output_buf));

			/* Use blog_des_entry with Ceph's client callback */
			ret = blog_des_entry(ceph_blog_ctx->logger, entry, output_buf,
			                    sizeof(output_buf), ceph_blog_client_des_callback);

			if (ret < 0) {
				seq_printf(s, "  Entry %d: [Error deserializing: %d]\n",
				          entry_count, ret);
			} else {
				char time_buf[64];
				u64 entry_jiffies = ctx->base_jiffies + entry->ts_delta;

				if (jiffies_to_formatted_time(entry_jiffies, time_buf,
					sizeof(time_buf)) < 0)
					strscpy(time_buf, "(invalid)", sizeof(time_buf));

				seq_printf(s,
					"  Entry %d (%s, ts_delta=%u, src=%u, client=%u, len=%u):\n",
					entry_count, time_buf, entry->ts_delta, entry->source_id,
					entry->client_id, entry->len);
				seq_printf(s, "    %s\n", output_buf);
			}
		}
		seq_printf(s, "\n");
	}

	spin_unlock(&ceph_blog_ctx->logger->lock);

	seq_printf(s, "Total contexts: %d\n", ctx_count);
	seq_printf(s, "Total entries: %d\n", entry_count);

	return 0;
}

static int blog_entries_open(struct inode *inode, struct file *file)
{
	return single_open(file, blog_entries_show, inode->i_private);
}

static const struct file_operations blog_entries_fops = {
	.open = blog_entries_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * blog_stats_show - Show BLOG statistics
 */
static int blog_stats_show(struct seq_file *s, void *p)
{
	seq_printf(s, "Ceph BLOG Statistics\n");
	seq_printf(s, "====================\n\n");

	if (!ceph_blog_ctx || !ceph_blog_ctx->logger) {
		seq_printf(s, "Ceph BLOG context not initialized\n");
		return 0;
	}

	seq_printf(s, "Ceph Module Logger State:\n");
	seq_printf(s, "  Total contexts allocated: %lu\n",
	          ceph_blog_ctx->logger->total_contexts_allocated);
	seq_printf(s, "  Next context ID: %llu\n", ceph_blog_ctx->logger->next_ctx_id);
	seq_printf(s, "  Next source ID: %u\n",
	          atomic_read(&ceph_blog_ctx->logger->next_source_id));

	seq_printf(s, "\nAllocation Batch:\n");
	seq_printf(s, "  Full magazines: %u\n", ceph_blog_ctx->logger->alloc_batch.nr_full);
	seq_printf(s, "  Empty magazines: %u\n", ceph_blog_ctx->logger->alloc_batch.nr_empty);

	seq_printf(s, "\nLog Batch:\n");
	seq_printf(s, "  Full magazines: %u\n", ceph_blog_ctx->logger->log_batch.nr_full);
	seq_printf(s, "  Empty magazines: %u\n", ceph_blog_ctx->logger->log_batch.nr_empty);

	return 0;
}

static int blog_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, blog_stats_show, inode->i_private);
}

static const struct file_operations blog_stats_fops = {
	.open = blog_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * blog_sources_show - Show all registered source locations
 */
static int blog_sources_show(struct seq_file *s, void *p)
{
	struct blog_source_info *source;
	u32 id;
	int count = 0;

	seq_printf(s, "Ceph BLOG Source Locations\n");
	seq_printf(s, "===========================\n\n");

	if (!ceph_blog_ctx || !ceph_blog_ctx->logger) {
		seq_printf(s, "Ceph BLOG context not initialized\n");
		return 0;
	}

	for (id = 1; id < BLOG_MAX_SOURCE_IDS; id++) {
		source = blog_get_source_info(ceph_blog_ctx->logger, id);
		if (!source || !source->file)
			continue;

		count++;
		seq_printf(s, "ID %u: %s:%s:%u\n", id,
		          source->file, source->func, source->line);
		seq_printf(s, "  Format: %s\n", source->fmt ? source->fmt : "(null)");
		seq_printf(s, "  Warnings: %d\n", source->warn_count);

#if BLOG_TRACK_USAGE
		seq_printf(s, "  NAPI usage: %d calls, %d bytes\n",
		          atomic_read(&source->napi_usage),
		          atomic_read(&source->napi_bytes));
		seq_printf(s, "  Task usage: %d calls, %d bytes\n",
		          atomic_read(&source->task_usage),
		          atomic_read(&source->task_bytes));
#endif
		seq_printf(s, "\n");
	}

	seq_printf(s, "Total registered sources: %d\n", count);

	return 0;
}

static int blog_sources_open(struct inode *inode, struct file *file)
{
	return single_open(file, blog_sources_show, inode->i_private);
}

static const struct file_operations blog_sources_fops = {
	.open = blog_sources_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * blog_clients_show - Show all registered Ceph clients
 */
static int blog_clients_show(struct seq_file *s, void *p)
{
	u32 id;
	int count = 0;
	const struct ceph_blog_client_info *info;

	seq_printf(s, "Ceph BLOG Registered Clients\n");
	seq_printf(s, "=============================\n\n");

	for (id = 1; id < CEPH_BLOG_MAX_CLIENTS; id++) {
		info = ceph_blog_get_client_info(id);
		if (!info || info->global_id == 0)
			continue;

		count++;

		seq_printf(s, "Client ID %u:\n", id);
		seq_printf(s, "  FSID: %pU\n", info->fsid);
		seq_printf(s, "  Global ID: %llu\n", info->global_id);
		seq_printf(s, "\n");
	}

	seq_printf(s, "Total registered clients: %d\n", count);

	return 0;
}

static int blog_clients_open(struct inode *inode, struct file *file)
{
	return single_open(file, blog_clients_show, inode->i_private);
}

static const struct file_operations blog_clients_fops = {
	.open = blog_clients_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/**
 * blog_clear_write - Clear all BLOG entries (write-only)
 */
static ssize_t blog_clear_write(struct file *file, const char __user *buf,
                                size_t count, loff_t *ppos)
{
    char cmd[16];

	if (count >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;

	cmd[count] = '\0';

	/* Only accept "clear" command */
	if (strncmp(cmd, "clear", 5) != 0)
		return -EINVAL;

    /* Reset all contexts */
    if (ceph_blog_ctx && ceph_blog_ctx->logger) {
        struct blog_tls_ctx *tls_ctx;
        spin_lock(&ceph_blog_ctx->logger->lock);
        list_for_each_entry(tls_ctx, &ceph_blog_ctx->logger->contexts, list) {
            blog_pagefrag_reset(&tls_ctx->pf);
        }
        spin_unlock(&ceph_blog_ctx->logger->lock);
        pr_info("ceph: BLOG entries cleared via debugfs\n");
    }

    return count;
}

static const struct file_operations blog_clear_fops = {
	.write = blog_clear_write,
};

/**
 * ceph_blog_debugfs_init - Initialize Ceph BLOG debugfs entries
 * @parent: Parent debugfs directory (usually ceph root)
 *
 * Return: 0 on success, negative error code on failure
 */
int ceph_blog_debugfs_init(struct dentry *parent)
{
	if (!parent)
		return -EINVAL;

	/* Create blog subdirectory */
	ceph_blog_debugfs_dir = debugfs_create_dir("blog", parent);
	if (!ceph_blog_debugfs_dir)
		return -ENOMEM;

	/* Create debugfs entries */
	debugfs_create_file("entries", 0444, ceph_blog_debugfs_dir, NULL,
	                   &blog_entries_fops);

	debugfs_create_file("stats", 0444, ceph_blog_debugfs_dir, NULL,
	                   &blog_stats_fops);

	debugfs_create_file("sources", 0444, ceph_blog_debugfs_dir, NULL,
	                   &blog_sources_fops);

	debugfs_create_file("clients", 0444, ceph_blog_debugfs_dir, NULL,
	                   &blog_clients_fops);

	debugfs_create_file("clear", 0200, ceph_blog_debugfs_dir, NULL,
	                   &blog_clear_fops);

	pr_info("ceph: BLOG debugfs initialized\n");
	return 0;
}
EXPORT_SYMBOL(ceph_blog_debugfs_init);

/**
 * ceph_blog_debugfs_cleanup - Clean up Ceph BLOG debugfs entries
 */
void ceph_blog_debugfs_cleanup(void)
{
	debugfs_remove_recursive(ceph_blog_debugfs_dir);
	ceph_blog_debugfs_dir = NULL;
	pr_info("ceph: BLOG debugfs cleaned up\n");
}
EXPORT_SYMBOL(ceph_blog_debugfs_cleanup);

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
