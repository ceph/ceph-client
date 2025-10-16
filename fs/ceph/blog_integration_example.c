// SPDX-License-Identifier: GPL-2.0
/*
 * Example integration code showing how Ceph uses BLOG
 *
 * This demonstrates the transition from ceph_san to BLOG with preserved
 * client ID mapping functionality.
 */

#include <linux/module.h>
#include <linux/ceph/ceph_debug.h>
#include <linux/ceph/ceph_blog.h>
#include <linux/ceph/libceph.h>

/*
 * Example 1: Simple logging without client context (like dout)
 * This doesn't store client_id
 */
void ceph_example_simple_log(void)
{
	int value = 42;
	const char *status = "active";

	/* Using BLOG for simple logging */
	CEPH_BLOG_LOG("Simple log: value=%d status=%s\n", value, status);

    /* (SAN legacy macro examples removed) */

	/* Traditional dout remains unchanged */
	dout("Traditional dout: value=%d\n", value);
}

/*
 * Example 2: Client-aware logging (like doutc and boutc)
 * This stores client_id for later deserialization
 */
void ceph_example_client_log(struct ceph_client *client)
{
	struct ceph_osd_request *req;
	u64 offset = 0x1000;
	u64 length = 0x4000;

	if (!client)
		return;

	/* Using BLOG with client context */
	CEPH_BLOG_LOG_CLIENT(client, "OSD request: offset=%llu length=%llu\n",
	                     offset, length);

    /* (SAN legacy macro examples removed) */

	/* Traditional doutc - shows [fsid global_id] in text logs */
	doutc(client, "Traditional doutc: processing request\n");

	/* boutc uses BLOG internally with client context */
	boutc(client, "Binary log with client: offset=%llu length=%llu\n",
	      offset, length);
}

/*
 * Example 3: Demonstrating client ID mapping preservation
 *
 * The client_id mapping is now handled by Ceph, not BLOG.
 * This preserves the exact functionality of ceph_san_check_client_id.
 */
void ceph_example_client_id_mapping(struct ceph_client *client)
{
	u32 client_id;
	const struct ceph_blog_client_info *info;

	if (!client)
		return;

	/* Get or allocate client ID for this Ceph client */
	client_id = ceph_blog_get_client_id(client);

	CEPH_BLOG_LOG_CLIENT(client,
	                     "Client registered with ID %u\n", client_id);

	/* The mapping is preserved in Ceph's blog_client.c */
	info = ceph_blog_get_client_info(client_id);
	if (info) {
		pr_info("Client %u maps to fsid=%pU global_id=%llu\n",
		        client_id, info->fsid, info->global_id);
	}
}

/*
 * Example 4: Debugfs integration
 *
 * The debugfs interface uses BLOG's deserialization with Ceph's
 * client callback to reconstruct the full log entries.
 */
void ceph_example_debugfs_usage(void)
{
	/*
	 * Debugfs files created by ceph_blog_debugfs_init():
	 *
	 * /sys/kernel/debug/ceph/blog/entries
	 *   - Shows all BLOG entries with client info deserialized
	 *   - Uses ceph_blog_client_des_callback to format [fsid gid]
	 *
	 * /sys/kernel/debug/ceph/blog/stats
	 *   - Shows BLOG statistics
	 *
	 * /sys/kernel/debug/ceph/blog/sources
	 *   - Shows all registered source locations
	 *
	 * /sys/kernel/debug/ceph/blog/clients
	 *   - Shows all registered Ceph clients with their mappings
	 *
	 * /sys/kernel/debug/ceph/blog/clear
	 *   - Write-only file to clear all BLOG entries
	 */
	pr_info("Debugfs available at /sys/kernel/debug/ceph/blog/\n");
}

/*
 * Example 5: Module initialization with BLOG
 */
static int __init ceph_blog_example_init(void)
{
	int ret;

	/* Initialize Ceph's BLOG integration */
	ret = ceph_blog_init();
	if (ret) {
		pr_err("Failed to initialize Ceph BLOG integration: %d\n", ret);
		return ret;
	}

	pr_info("Ceph BLOG integration example loaded\n");

	/* Note: In real usage, blog_init() would be called by BLOG module
	 * and ceph_blog_init() would be called by Ceph FS module init
	 */

	return 0;
}

static void __exit ceph_blog_example_exit(void)
{
	/* Clean up Ceph's BLOG integration */
	ceph_blog_cleanup();

	pr_info("Ceph BLOG integration example unloaded\n");
}

module_init(ceph_blog_example_init);
module_exit(ceph_blog_example_exit);

MODULE_DESCRIPTION("Ceph BLOG Integration Example");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ceph Development Team");
