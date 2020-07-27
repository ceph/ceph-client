/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ceph fscrypt functionality
 */

#ifndef _CEPH_CRYPTO_H
#define _CEPH_CRYPTO_H

#include <linux/fscrypt.h>

struct ceph_fscrypt_auth {
	__le32	cfa_version;
	__le32	cfa_blob_len;
	u8	cfa_blob[FSCRYPT_SET_CONTEXT_MAX_SIZE];
} __packed;

#ifdef CONFIG_FS_ENCRYPTION
#define CEPH_FSCRYPT_AUTH_VERSION	1
void ceph_fscrypt_set_ops(struct super_block *sb);

#else /* CONFIG_FS_ENCRYPTION */

static inline void ceph_fscrypt_set_ops(struct super_block *sb)
{
}

#endif /* CONFIG_FS_ENCRYPTION */

#endif
