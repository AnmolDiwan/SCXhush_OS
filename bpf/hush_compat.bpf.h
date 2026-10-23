/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hush_compat.bpf.h - the one place scx_hush names sched_ext kernel APIs.
 *
 * NFR-9: sched_ext ops, constants and scx_bpf_* kfuncs carry no ABI
 * guarantee and have been renamed before (scx_bpf_dispatch became
 * scx_bpf_dsq_insert; scx_bpf_dsq_move_to_local gained enq_flags in v7.1).
 * scx_hush.bpf.c only uses the hush_* wrappers below. When the kernel API
 * moves, this header and the pinned scx commit in scripts/fetch-deps.sh are
 * the only things to update.
 *
 * The heavy lifting (weak ksym fallbacks for older kernels, enum values read
 * from the running kernel's BTF at load time) comes from the sched-ext/scx
 * project headers, which this header wraps.
 */
#ifndef __HUSH_COMPAT_BPF_H
#define __HUSH_COMPAT_BPF_H

#include <scx/common.bpf.h>

/* Dispatch queue identifiers and flags. */
#define HUSH_DSQ_LOCAL			SCX_DSQ_LOCAL
#define HUSH_DSQ_LOCAL_ON(cpu)		(SCX_DSQ_LOCAL_ON | (u64)(cpu))
#define HUSH_ENQ_WAKEUP			SCX_ENQ_WAKEUP
#define HUSH_SLICE_DFL			SCX_SLICE_DFL

/* DSQ lifecycle and insertion. */
#define hush_create_dsq(id)		scx_bpf_create_dsq((id), -1)
#define hush_insert(p, dsq, slice, fl)	scx_bpf_dsq_insert((p), (dsq), (slice), (fl))
#define hush_insert_vtime(p, dsq, slice, vt, fl) \
	scx_bpf_dsq_insert_vtime((p), (dsq), (slice), (vt), (fl))
#define hush_move_to_local(dsq)		scx_bpf_dsq_move_to_local((dsq), 0)
#define hush_nr_queued(dsq)		scx_bpf_dsq_nr_queued(dsq)

/* Iterating a DSQ and moving the task under the iterator (dispatch only). */
#define hush_dsq_for_each(p, dsq)	bpf_for_each(scx_dsq, p, (dsq), 0)
#define HUSH_DSQ_ITER			BPF_FOR_EACH_ITER
#define hush_dsq_move(it, p, dsq)	scx_bpf_dsq_move((it), (p), (dsq), 0)
#define hush_dsq_move_vtime(it, p, dsq)	scx_bpf_dsq_move_vtime((it), (p), (dsq), 0)
#define hush_dsq_move_set_slice(it, s)	scx_bpf_dsq_move_set_slice((it), (s))
#define hush_dsq_move_set_vtime(it, v)	scx_bpf_dsq_move_set_vtime((it), (v))

/* CPU selection and preemption. */
#define hush_select_cpu_dfl(p, prev, wf, idle) \
	scx_bpf_select_cpu_dfl((p), (prev), (wf), (idle))
#define hush_kick_preempt(cpu)		scx_bpf_kick_cpu((cpu), SCX_KICK_PREEMPT)
#define hush_task_cpu(p)		scx_bpf_task_cpu(p)
#define hush_nr_cpu_ids()		scx_bpf_nr_cpu_ids()

/* Time and errors. */
#define hush_now()			scx_bpf_now()
#define hush_error(fmt, args...)	scx_bpf_error(fmt, ##args)

/* Task references by TID (init pid namespace). */
#define hush_task_from_tid(tid)		bpf_task_from_pid(tid)
#define hush_task_release(p)		bpf_task_release(p)

/* Exit info shared with hushd through the skeleton (§10.4 exit report). */
#define HUSH_UEI_DEFINE(name)		UEI_DEFINE(name)
#define HUSH_UEI_RECORD(name, ei)	UEI_RECORD(name, ei)

/* Struct ops definition. */
#define HUSH_OPS_DEFINE(name, ...)	SCX_OPS_DEFINE(name, __VA_ARGS__)
#define HUSH_OPS(name, args...)		BPF_STRUCT_OPS(name, ##args)
#define HUSH_OPS_SLEEPABLE(name, args...) BPF_STRUCT_OPS_SLEEPABLE(name, ##args)

#endif /* __HUSH_COMPAT_BPF_H */
