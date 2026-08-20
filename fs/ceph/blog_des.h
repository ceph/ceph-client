/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BLOG record deserialization.
 */
#ifndef _FS_CEPH_BLOG_DES_H
#define _FS_CEPH_BLOG_DES_H

#include <linux/types.h>

struct blog_log_entry;
struct blog_logger;

int blog_des_reconstruct(const char *fmt, const void *buffer,
			 size_t size, char *out, size_t out_size);

#endif /* _FS_CEPH_BLOG_DES_H */
