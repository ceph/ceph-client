// SPDX-License-Identifier: GPL-2.0
/*
 * Ceph client ID management for BLOG integration
 *
 * Maintains mapping between Ceph's fsid/global_id and BLOG client IDs
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ceph/ceph_debug.h>
#include <linux/ceph/libceph.h>
#include <linux/ceph/ceph_blog.h>
#include <linux/blog/blog.h>

/* Ceph's BLOG module context */
struct blog_module_context *ceph_blog_ctx;
EXPORT_SYMBOL(ceph_blog_ctx);

/* Ceph's logger - direct access to the logger from module context */
struct blog_logger *ceph_logger;
EXPORT_SYMBOL(ceph_logger);

/* Global client mapping state */
static struct {
	struct ceph_blog_client_info client_map[CEPH_BLOG_MAX_CLIENTS];
	u32 next_client_id;
	spinlock_t lock;
	bool initialized;
} ceph_blog_state = {
	.next_client_id = 1,  /* Start from 1, 0 is reserved */
	.lock = __SPIN_LOCK_UNLOCKED(ceph_blog_state.lock),
	.initialized = false,
};

/**
 * ceph_blog_init - Initialize Ceph BLOG integration
 *
 * Creates a module-specific BLOG context for Ceph and initializes
 * the client ID mapping state.
 *
 * Return: 0 on success, negative error code on failure
 */
int ceph_blog_init(void)
{
	if (ceph_blog_state.initialized)
		return 0;

	/* Create Ceph's module-specific BLOG context */
	ceph_blog_ctx = blog_module_init("ceph");
	if (!ceph_blog_ctx) {
		pr_err("ceph: Failed to initialize BLOG module context\n");
		return -ENOMEM;
	}

	/* Set ceph_logger for direct access to the logger */
	ceph_logger = ceph_blog_ctx->logger;

	/* Initialize client mapping state */
	memset(ceph_blog_state.client_map, 0, sizeof(ceph_blog_state.client_map));
	ceph_blog_state.next_client_id = 1;
	ceph_blog_state.initialized = true;

	pr_info("ceph: BLOG module context and client mapping initialized\n");
	return 0;
}
EXPORT_SYMBOL(ceph_blog_init);

/**
 * ceph_blog_cleanup - Clean up Ceph BLOG integration
 *
 * Cleans up Ceph's module-specific BLOG context and client mappings.
 */
void ceph_blog_cleanup(void)
{
	if (!ceph_blog_state.initialized)
		return;

	/* Clean up client mapping state */
	spin_lock(&ceph_blog_state.lock);
	memset(ceph_blog_state.client_map, 0, sizeof(ceph_blog_state.client_map));
	ceph_blog_state.next_client_id = 1;
	ceph_blog_state.initialized = false;
	spin_unlock(&ceph_blog_state.lock);

	/* Clean up module-specific BLOG context */
	if (ceph_blog_ctx) {
		blog_module_cleanup(ceph_blog_ctx);
		ceph_blog_ctx = NULL;
		ceph_logger = NULL;
	}

	pr_info("ceph: BLOG module context and client mapping cleaned up\n");
}
EXPORT_SYMBOL(ceph_blog_cleanup);

/**
 * ceph_blog_check_client_id - Check if a client ID matches the given fsid:global_id pair
 * @id: Client ID to check
 * @fsid: Client FSID to compare
 * @global_id: Client global ID to compare
 *
 * This preserves the exact functionality of ceph_san_check_client_id.
 * Returns the actual ID of the pair. If the given ID doesn't match, scans for
 * existing matches or allocates a new ID if no match is found.
 *
 * Return: Client ID for this fsid/global_id pair
 */
u32 ceph_blog_check_client_id(u32 id, const char *fsid, u64 global_id)
{
	u32 found_id = 0;
	struct ceph_blog_client_info *entry;
	u32 max_id;

	if (unlikely(!ceph_blog_state.initialized)) {
		WARN_ON_ONCE(1);  /* Should never happen - init_ceph() initializes BLOG */
		return 0;  /* Drop the log entry */
	}

	/* First check if the given ID matches */
	if (id != 0 && id < CEPH_BLOG_MAX_CLIENTS) {
		entry = &ceph_blog_state.client_map[id];
		if (memcmp(entry->fsid, fsid, sizeof(entry->fsid)) == 0 &&
		    entry->global_id == global_id) {
			found_id = id;
			goto out_fast;
		}
	}

	spin_lock(&ceph_blog_state.lock);
	max_id = ceph_blog_state.next_client_id;

	/* Scan for existing match */
	for (id = 1; id < max_id && id < CEPH_BLOG_MAX_CLIENTS; id++) {
		entry = &ceph_blog_state.client_map[id];
		if (memcmp(entry->fsid, fsid, sizeof(entry->fsid)) == 0 &&
		    entry->global_id == global_id) {
			found_id = id;
			goto out;
		}
	}

	/* No match found, allocate new ID */
	found_id = ceph_blog_state.next_client_id++;
	if (found_id >= CEPH_BLOG_MAX_CLIENTS) {
		/* If we run out of IDs, reuse ID 1 */
		pr_warn("ceph: BLOG client ID overflow, reusing ID 1\n");
		found_id = 1;
		ceph_blog_state.next_client_id = 2;
	}
	/* Use %pU to print fsid like the rest of Ceph does */
	pr_info("ceph: allocating new BLOG client ID %u for fsid=%pU global_id=%llu\n",
		found_id, fsid, global_id);

	entry = &ceph_blog_state.client_map[found_id];
	memcpy(entry->fsid, fsid, sizeof(entry->fsid));
	entry->global_id = global_id;

out:
	spin_unlock(&ceph_blog_state.lock);
out_fast:
	return found_id;
}
EXPORT_SYMBOL(ceph_blog_check_client_id);

/**
 * ceph_blog_get_client_info - Get client info for a given ID
 * @id: Client ID
 *
 * Return: Client information for this ID, or NULL if invalid
 */
const struct ceph_blog_client_info *ceph_blog_get_client_info(u32 id)
{
	if (!ceph_blog_state.initialized || id == 0 || id >= CEPH_BLOG_MAX_CLIENTS)
		return NULL;
	return &ceph_blog_state.client_map[id];
}
EXPORT_SYMBOL(ceph_blog_get_client_info);

/**
 * ceph_blog_client_des_callback - Deserialization callback for Ceph client info
 * @buf: Output buffer
 * @size: Buffer size
 * @client_id: Client ID to deserialize
 *
 * This is the callback that BLOG will use to deserialize client information.
 *
 * Return: Number of bytes written to buffer
 */
int ceph_blog_client_des_callback(char *buf, size_t size, u8 client_id)
{
	const struct ceph_blog_client_info *info;

	if (!buf || !size)
		return -EINVAL;

	info = ceph_blog_get_client_info(client_id);
	if (!info) {
		return snprintf(buf, size, "[unknown_client_%u]", client_id);
	}

	/* Use %pU to format fsid, matching doutc and other Ceph client logging */
	return snprintf(buf, size, "[%pU %llu] ",
			info->fsid, info->global_id);
}
EXPORT_SYMBOL(ceph_blog_client_des_callback);

/**
 * ceph_blog_get_client_id - Get or allocate client ID for a Ceph client
 * @client: Ceph client structure
 *
 * Return: Client ID for this client
 */
u32 ceph_blog_get_client_id(struct ceph_client *client)
{
	if (!client)
		return 0;

	/*
	 * No caching - ceph_blog_check_client_id has internal fast path
	 * that checks the provided ID first before scanning
	 */
	return ceph_blog_check_client_id(0,
					  client->fsid.fsid,
					  client->monc.auth->global_id);
}
EXPORT_SYMBOL(ceph_blog_get_client_id);
