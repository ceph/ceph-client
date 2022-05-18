// SPDX-License-Identifier: GPL-2.0-or-later
/* Direct I/O support.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/sched/mm.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * Copy all of the data from the folios in the source xarray into the
 * destination iterator.  We cannot step through and kmap the dest iterator if
 * it's an iovec, so we have to step through the xarray and drop the RCU lock
 * each time.
 */
static int netfs_copy_xarray_to_iter(struct netfs_io_request *rreq,
				     struct xarray *xa, struct iov_iter *dst,
				     unsigned long long start, size_t avail)
{
	struct folio *folio;
	void *base;
	pgoff_t index = start / PAGE_SIZE;
	size_t len, copied, count = min(avail, iov_iter_count(dst));

	XA_STATE(xas, xa, index);

	_enter("%zx", count);

	if (!count) {
		trace_netfs_failure(rreq, NULL, -EIO, netfs_fail_dio_read_zero);
		return -EIO;
	}

	len = PAGE_SIZE - offset_in_page(start);
	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) {
		size_t offset;

		if (xas_retry(&xas, folio))
			continue;

		/* There shouldn't be a need to call xas_pause() as no one else
		 * should be modifying the xarray we're iterating over.
		 * Really, we only need the RCU readlock to keep lockdep happy
		 * inside xas_for_each().
		 */
		rcu_read_unlock();

		offset = offset_in_folio(folio, start);
		kdebug("folio %lx +%zx [%llx]", folio->index, offset, start);

		while (offset < folio_size(folio)) {
			len = min(count, len);

			base = kmap_local_folio(folio, offset);
			copied = copy_to_iter(base, len, dst);
			kunmap_local(base);
			if (copied != len)
				goto out;
			count -= len;
			if (count == 0)
				goto out;

			start += len;
			offset += len;
			len = PAGE_SIZE;
		}

		rcu_read_lock();
	}

	rcu_read_unlock();
out:
	_leave(" = %zx", count);
	return count ? -EFAULT : 0;
}

int netfs_dio_copy_to_dest(struct netfs_io_request *rreq)
{
	struct iov_iter *dest_iter = &rreq->direct_iter;
	struct kiocb *iocb = rreq->iocb;
	unsigned long long start = rreq->start;

	_enter("%zx/%zx @%llx %u", rreq->transferred, rreq->len, start, rreq->buffering);

	if (rreq->buffering != NETFS_BOUNCE)
		return 0;

	if (start < iocb->ki_pos) {
		if (rreq->transferred <= iocb->ki_pos - start) {
			trace_netfs_failure(rreq, NULL, -EIO, netfs_fail_dio_read_short);
			return -EIO;
		}
		rreq->len = rreq->transferred;
		rreq->transferred -= iocb->ki_pos - start;
	}

	if (rreq->transferred > iov_iter_count(dest_iter))
		rreq->transferred = iov_iter_count(dest_iter);

	_debug("xfer %zx/%zx @%llx", rreq->transferred, rreq->len, iocb->ki_pos);
	return netfs_copy_xarray_to_iter(rreq, &rreq->bounce, dest_iter,
					 iocb->ki_pos, rreq->transferred);
}

/**
 * netfs_direct_read_iter - Perform a direct I/O read
 * @iocb: The I/O control descriptor describing the read
 * @iter: The output buffer (also specifies read length)
 */
ssize_t netfs_direct_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_io_request *rreq;
	ssize_t n;

	_enter("");

	rreq = netfs_alloc_request(iocb->ki_filp->f_mapping, iocb->ki_filp,
				   iocb->ki_pos, iov_iter_count(iter),
				   NETFS_DIO_READ);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);

	netfs_stat(&netfs_n_rh_dio_read);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_dio_read);

	/* Ideally we'd use NETFS_DIRECT, but iovec-class iterators sometimes
	 * fault when passed to sock_sendmsg().  Further, we *must* copy the
	 * iterator if we're going to operate asynchronously.
	 */
	rreq->buffering = NETFS_DIRECT_BV;

	/* If this is an async op, we have to keep track of the destination
	 * buffer for ourselves as the caller's iterator will be trashed when
	 * we return.
	 *
	 * In such a case, extract an iterator to represent as much of the the
	 * output buffer as we can manage.  Note that the extraction might not
	 * be able to allocate a sufficiently large bvec array and may shorten
	 * the request.
	 */
	switch (rreq->buffering) {
	case NETFS_DIRECT:
		rreq->direct_iter = *iter;
		rreq->len = iov_iter_count(&rreq->direct_iter);
		break;
	case NETFS_DIRECT_BV:
		n = extract_iter_to_iter(iter, rreq->len, &rreq->direct_iter,
					 &rreq->direct_bv);
		if (n < 0) {
			netfs_put_request(rreq, false, netfs_rreq_trace_put_discard);
			return n;
		}
		rreq->direct_bv_count = n;
		rreq->len = iov_iter_count(&rreq->direct_iter);
		break;
	default:
		BUG();
	}

	rreq->iocb = iocb;

	return netfs_begin_read(rreq, is_sync_kiocb(iocb));
}
EXPORT_SYMBOL(netfs_direct_read_iter);
