#ifndef SCX_COMPAT_H
#define SCX_COMPAT_H

/*
 * scx_compat.h - Isolation layer for sched_ext kfuncs, constants, and ops.
 * Satisfies NFR-9: "Kernel API names isolated in one header, because sched_ext
 * kfuncs have no ABI stability guarantee."
 */

#include "scx_hush_types.h"

/* Common sched_ext constants */
#ifndef SCX_DSQ_GLOBAL
#define SCX_DSQ_GLOBAL          0
#endif

#ifndef SCX_DSQ_LOCAL
#define SCX_DSQ_LOCAL           1
#endif

#ifndef SCX_DSQ_LOCAL_ON
#define SCX_DSQ_LOCAL_ON        0x8000000000000000ULL
#endif

#ifndef SCX_KICK_PREEMPT
#define SCX_KICK_PREEMPT        (1ULL << 0)
#endif

#ifndef SCX_KICK_WAIT
#define SCX_KICK_WAIT           (1ULL << 1)
#endif

#ifndef SCX_ENQ_WAKEUP
#define SCX_ENQ_WAKEUP          (1ULL << 0)
#endif

#ifndef SCX_ENQ_HEAD
#define SCX_ENQ_HEAD            (1ULL << 1)
#endif

#ifndef SCX_ENQ_PREEMPT
#define SCX_ENQ_PREEMPT         (1ULL << 2)
#endif

#ifndef SCX_DEQ_SLEEP
#define SCX_DEQ_SLEEP           (1ULL << 0)
#endif

/*
 * Kernel / BPF kfunc declarations when compiling under BPF target.
 * For user space mock or testing, wrappers are provided.
 */
#if defined(__bpf__) || defined(BPF_TARGET)

#define SCX_OPS_NAME "scx_hush"

/* Modern sched_ext kfunc signatures (Linux 6.12+) */
extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq_id, u64 slice, u64 vtime, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
extern u64 scx_bpf_now(void) __ksym;
extern s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;
extern void scx_bpf_exit(s32 exit_code, const char *fmt, ...) __ksym;

#endif /* __bpf__ */

#endif /* SCX_COMPAT_H */

