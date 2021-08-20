// SPDX-License-Identifier: GPL-2.0-only
/* Miscellaneous routines.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/swap.h>
#include "internal.h"

/*
 * Invalidate part or all of a folio
 * - release a folio and clean up its private data if offset is 0 (indicating
 *   the entire folio)
 */
void netfs_invalidate_folio(struct folio *folio, size_t offset, size_t length)
{
	_enter("{%lx},%lx,%lx", folio_index(folio), offset, length);

	folio_wait_fscache(folio);
}
EXPORT_SYMBOL(netfs_invalidate_folio);

/*
 * Release a folio and clean up its private state if it's not busy
 * - return true if the folio can now be released, false if not
 */
int netfs_releasepage(struct page *page, gfp_t gfp)
{
	struct folio *folio = page_folio(page);

	_enter("");

	if (PagePrivate(page))
		return 0;
	if (folio_test_fscache(folio)) {
		if (current_is_kswapd() || !(gfp & __GFP_FS))
			return false;
		folio_wait_fscache(folio);
	}

	fscache_note_page_release(netfs_i_cookie(folio_inode(folio)));
	return true;
}
EXPORT_SYMBOL(netfs_releasepage);
