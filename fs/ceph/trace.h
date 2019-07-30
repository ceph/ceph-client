/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ceph

#if !defined(_CEPH_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _CEPH_TRACE_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>
#include "super.h"

const char *trace_ceph_cap_string(struct trace_seq *p, int caps);
#define show_caps(caps) ({ trace_ceph_cap_string(p, caps); })

#define show_snapid(snap)	\
	__print_symbolic_u64(snap, {CEPH_NOSNAP, "NOSNAP" })

DECLARE_EVENT_CLASS(ceph_cap_class,
	TP_PROTO(struct ceph_cap *cap),
	TP_ARGS(cap),
	TP_STRUCT__entry(
		__field(u64, ino)
		__field(u64, snap)
		__field(int, issued)
		__field(int, implemented)
		__field(int, mds)
		__field(int, mds_wanted)
	),
	TP_fast_assign(
		__entry->ino = cap->ci->i_vino.ino;
		__entry->snap = cap->ci->i_vino.snap;
		__entry->issued = cap->issued;
		__entry->implemented = cap->implemented;
		__entry->mds = cap->mds;
		__entry->mds_wanted = cap->mds_wanted;
	),
	TP_printk("ino=%s:0x%llx mds=%d issued=%s implemented=%s mds_wanted=%s",
		show_snapid(__entry->snap), __entry->ino, __entry->mds,
		show_caps(__entry->issued), show_caps(__entry->implemented),
		show_caps(__entry->mds_wanted))
)

#define DEFINE_CEPH_CAP_EVENT(name)             \
DEFINE_EVENT(ceph_cap_class, ceph_##name,       \
	TP_PROTO(struct ceph_cap *cap),		\
	TP_ARGS(cap))

DEFINE_CEPH_CAP_EVENT(add_cap);
DEFINE_CEPH_CAP_EVENT(remove_cap);
DEFINE_CEPH_CAP_EVENT(handle_cap_grant);

#endif /* _CEPH_TRACE_H */

#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
