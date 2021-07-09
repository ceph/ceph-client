// SPDX-License-Identifier: GPL-2.0-only
/* Miscellaneous routines.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/swap.h>
#include "internal.h"

/*
 * Attach a folio to the buffer and maybe set marks on it to say that we need
 * to put the folio later and twiddle the pagecache flags.
 */
int netfs_xa_store_and_mark(struct xarray *xa, unsigned long index,
			    struct folio *folio, bool put_mark,
			    bool pagecache_mark, gfp_t gfp_mask)
{
	XA_STATE_ORDER(xas, xa, index, folio_order(folio));

retry:
	xas_lock(&xas);
	for (;;) {
		xas_store(&xas, folio);
		if (!xas_error(&xas))
			break;
		xas_unlock(&xas);
		if (!xas_nomem(&xas, gfp_mask))
			return xas_error(&xas);
		goto retry;
	}

	if (put_mark)
		xas_set_mark(&xas, NETFS_BUF_PUT_MARK);
	if (pagecache_mark)
		xas_set_mark(&xas, NETFS_BUF_PAGECACHE_MARK);
	xas_unlock(&xas);
	return xas_error(&xas);
}

/*
 * Create the specified range of folios in the buffer attached to the read
 * request.  The folios are marked with NETFS_BUF_PUT_MARK so that we know that
 * these need freeing later.
 */
int netfs_add_folios_to_buffer(struct xarray *buffer,
			       struct address_space *mapping,
			       pgoff_t index, pgoff_t to, gfp_t gfp_mask)
{
	struct folio *folio;
	int ret;

	if (to + 1 == index) /* Page range is inclusive */
		return 0;

	do {
		/* TODO: Figure out what order folio can be allocated here */
		folio = filemap_alloc_folio(readahead_gfp_mask(mapping), 0);
		if (!folio)
			return -ENOMEM;
		folio->index = index;
		ret = netfs_xa_store_and_mark(buffer, index, folio,
					      true, false, gfp_mask);
		if (ret < 0) {
			folio_put(folio);
			return ret;
		}

		index += folio_nr_pages(folio);
	} while (index <= to && index != 0);

	return 0;
}

/*
 * Set up a buffer into which to data will be read or decrypted/decompressed.
 * The folios to be read into are attached to this buffer and the gaps filled
 * in to form a continuous region.
 */
int netfs_set_up_buffer(struct xarray *buffer,
			struct address_space *mapping,
			struct readahead_control *ractl,
			struct folio *keep,
			pgoff_t have_index, unsigned int have_folios)
{
	struct folio *folio;
	gfp_t gfp_mask = readahead_gfp_mask(mapping);
	unsigned int want_folios = have_folios;
	pgoff_t want_index = have_index;
	int ret;

	ret = netfs_add_folios_to_buffer(buffer, mapping, want_index,
					 have_index - 1, gfp_mask);
	if (ret < 0)
		return ret;
	have_folios += have_index - want_index;

	ret = netfs_add_folios_to_buffer(buffer, mapping,
					 have_index + have_folios,
					 want_index + want_folios - 1,
					 gfp_mask);
	if (ret < 0)
		return ret;

	/* Transfer the folios proposed by the VM into the buffer and take refs
	 * on them.  The locks will be dropped in netfs_rreq_unlock().
	 */
	if (ractl) {
		while ((folio = readahead_folio(ractl))) {
			folio_get(folio);
			if (folio == keep)
				folio_get(folio);
			ret = netfs_xa_store_and_mark(buffer, folio->index, folio,
						      true, true, gfp_mask);
			if (ret < 0) {
				if (folio != keep)
					folio_unlock(folio);
				folio_put(folio);
				return ret;
			}
		}
	} else {
		folio_get(keep);
		ret = netfs_xa_store_and_mark(buffer, keep->index, keep,
					      true, true, gfp_mask);
		if (ret < 0) {
			folio_put(keep);
			return ret;
		}
	}
	return 0;
}

/*
 * Clear an xarray buffer, putting a ref on the folios that have
 * NETFS_BUF_PUT_MARK set.
 */
void netfs_clear_buffer(struct xarray *buffer)
{
	struct folio *folio;
	XA_STATE(xas, buffer, 0);

	rcu_read_lock();
	xas_for_each_marked(&xas, folio, ULONG_MAX, NETFS_BUF_PUT_MARK) {
		folio_put(folio);
	}
	rcu_read_unlock();
	xa_destroy(buffer);
}

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
