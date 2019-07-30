// SPDX-License-Identifier: GPL-2.0
#define CREATE_TRACE_POINTS
#include <linux/ceph/ceph_debug.h>
#include "trace.h"

#define CEPH_CAP_BASE_MASK	(CEPH_CAP_GSHARED|CEPH_CAP_GEXCL)
#define CEPH_CAP_FILE_MASK	(CEPH_CAP_GSHARED |	\
				 CEPH_CAP_GEXCL |	\
				 CEPH_CAP_GCACHE |	\
				 CEPH_CAP_GRD |		\
				 CEPH_CAP_GWR |		\
				 CEPH_CAP_GBUFFER |	\
				 CEPH_CAP_GWREXTEND |	\
				 CEPH_CAP_GLAZYIO)

static void
trace_gcap_string(struct trace_seq *p, int c)
{
	if (c & CEPH_CAP_GSHARED)
		trace_seq_putc(p, 's');
	if (c & CEPH_CAP_GEXCL)
		trace_seq_putc(p, 'x');
	if (c & CEPH_CAP_GCACHE)
		trace_seq_putc(p, 'c');
	if (c & CEPH_CAP_GRD)
		trace_seq_putc(p, 'r');
	if (c & CEPH_CAP_GWR)
		trace_seq_putc(p, 'w');
	if (c & CEPH_CAP_GBUFFER)
		trace_seq_putc(p, 'b');
	if (c & CEPH_CAP_GWREXTEND)
		trace_seq_putc(p, 'a');
	if (c & CEPH_CAP_GLAZYIO)
		trace_seq_putc(p, 'l');
}

const char *
trace_ceph_cap_string(struct trace_seq *p, int caps)
{
	int c;
	const char *ret = trace_seq_buffer_ptr(p);

	if (caps == 0) {
		trace_seq_putc(p, '-');
		goto out;
	}

	if (caps & CEPH_CAP_PIN)
		trace_seq_putc(p, 'p');

	c = (caps >> CEPH_CAP_SAUTH) & CEPH_CAP_BASE_MASK;
	if (c) {
		trace_seq_putc(p, 'A');
		trace_gcap_string(p, c);
	}

	c = (caps >> CEPH_CAP_SLINK) & CEPH_CAP_BASE_MASK;
	if (c) {
		trace_seq_putc(p, 'L');
		trace_gcap_string(p, c);
	}

	c = (caps >> CEPH_CAP_SXATTR) & CEPH_CAP_BASE_MASK;
	if (c) {
		trace_seq_putc(p, 'X');
		trace_gcap_string(p, c);
	}

	c = (caps >> CEPH_CAP_SFILE) & CEPH_CAP_FILE_MASK;
	if (c) {
		trace_seq_putc(p, 'F');
		trace_gcap_string(p, c);
	}
out:
	trace_seq_putc(p, '\0');
	return ret;
}
