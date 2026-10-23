/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hush_intf.h - ABI shared by the scx_hush BPF programs and user space.
 *
 * Everything in this header crosses the kernel/user boundary through a BPF
 * map, so every struct uses fixed-width fields and explicit padding. Change
 * a layout here and both sides rebuild together; there is no versioning.
 */
#ifndef __HUSH_INTF_H
#define __HUSH_INTF_H

#ifndef __bpf__
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
#endif

/* Task classes (FR-1). HUSH_CLASS_NONE only appears in maps and cpu_ctx. */
enum hush_class {
	HUSH_CLASS_NONE = 0,
	HUSH_CLASS_FG = 1,
	HUSH_CLASS_NORMAL = 2,
	HUSH_CLASS_BG = 3,
	HUSH_NR_CLASSES = 4,
};

/* Why a task has its base class; reported by `hushctl class`. */
enum hush_reason {
	HUSH_RSN_DEFAULT = 0,	/* no rule matched */
	HUSH_RSN_PID = 1,	/* hushctl promote/demote <pid> */
	HUSH_RSN_CGROUP = 2,
	HUSH_RSN_COMM = 3,
	HUSH_RSN_UID = 4,
	HUSH_RSN_INHERIT = 5,	/* FR-4: inherited from parent at fork */
	HUSH_RSN_KTHREAD = 6,	/* §7.7: kernel threads are always NORMAL */
};

/* Custom dispatch queues (§7.2). */
#define HUSH_FG_DSQ 1ULL
#define HUSH_NORMAL_DSQ 2ULL
#define HUSH_BG_DSQ 3ULL

/* Defaults (§9.2). hushd overrides them from the policy file. */
#define HUSH_DFL_FG_SLICE_NS (5ULL * 1000 * 1000)
#define HUSH_DFL_NORMAL_SLICE_NS (10ULL * 1000 * 1000)
#define HUSH_DFL_BG_SLICE_NS (20ULL * 1000 * 1000)
#define HUSH_DFL_GUARD_NS (2000ULL * 1000 * 1000)
#define HUSH_DFL_BOOST_NS (50ULL * 1000 * 1000)
#define HUSH_DFL_BOOST_CAP_PCT 10
#define HUSH_DFL_WATCHDOG_MS 30000	/* sched_ext's maximum */
#define HUSH_DFL_DSTATE_THRESH_NS (10ULL * 1000 * 1000)
#define HUSH_DFL_ESCAPE_NS (20ULL * 1000 * 1000)
#define HUSH_DFL_FALLBACK_WINDOW_NS (10ULL * 1000 * 1000)

#define HUSH_BOOST_WINDOW_NS (1000ULL * 1000 * 1000) /* 10% cap window */
#define HUSH_BOOST_WALK_MAX 64	/* §8.2: BG_DSQ entries scanned per boost pass */
#define HUSH_MAX_CPUS 512	/* bound for the §7.4 preemption scan */
#define HUSH_COMM_LEN 16

#define HUSH_MAP_CGROUP_MAX 4096
#define HUSH_MAP_COMM_MAX 256
#define HUSH_MAP_UID_MAX 256
#define HUSH_MAP_PID_MAX 1024

/* hush_config.flags */
#define HUSH_F_INVERSION (1U << 0)	/* tiers 2/3/fallback act (B5 clears it) */
#define HUSH_F_TIER3 (1U << 1)		/* glibc layout validated by selftest */
#define HUSH_F_FALLBACK (1U << 2)	/* same-process fallback boost */
#define HUSH_F_DSTATE (1U << 3)		/* tier 4 D-state escape */
#define HUSH_F_TRACE (1U << 4)		/* emit wakeup latency to trace_rb */
#define HUSH_F_HINTS (1U << 5)		/* honour libhush hints (tier 1) */

/* Boost sources, indexes hush_stats.boosts[]. */
enum hush_boost_src {
	HUSH_BOOST_HINT = 0,
	HUSH_BOOST_PI = 1,
	HUSH_BOOST_GLIBC = 2,
	HUSH_BOOST_FALLBACK = 3,
	HUSH_NR_BOOST_SRC = 4,
};

/* config map, single entry, written by hushd. */
struct hush_config {
	u64 slice_ns[HUSH_NR_CLASSES];	/* indexed by class; [0] unused */
	u64 guard_ns;
	u64 hard_guard_ns;		/* watchdog/2, see plan §2.2 item 4 */
	u64 boost_ns;
	u64 dstate_thresh_ns;
	u64 escape_ns;
	u64 fallback_window_ns;
	u32 boost_cap_pct;
	u32 policy_gen;			/* bumped on every reload/promote/demote */
	u32 flags;			/* HUSH_F_* */
	u32 __pad;
};

/* task_ctx, BPF task-local storage (§10.2). */
struct task_ctx {
	u64 boost_until;	/* effective class is FG while now < this */
	u64 boost_uaddr;	/* futex address the boost was granted for */
	u64 boost_win_start;	/* start of the current 1 s cap window */
	u64 boost_used_ns;	/* boosted runtime in the current window */
	u64 runnable_at;	/* last time the task became runnable */
	u64 wait_uaddr;		/* futex this task is blocked on, if any */
	u64 dsleep_at;		/* start of uninterruptible sleep (tier 4) */
	u64 cgid;		/* cgroup ID the class was resolved under */
	u32 policy_gen;		/* generation at last classification */
	u32 boost_waiter;	/* TID of the FG waiter that caused the boost */
	u16 crit_depth;		/* hush_critical_enter nesting */
	u8 base_class;		/* class from policy */
	u8 reason;		/* enum hush_reason */
	u8 inherit_class;	/* class inherited at fork, 0 if none */
	u8 last_class;		/* effective class at last enqueue */
	u8 boost_src;		/* enum hush_boost_src of the active boost */
	u8 run_class;		/* effective class while on CPU, for charging */
	u8 tflags;		/* HUSH_TF_* */
	u8 __pad[7];
};

/* task_ctx.tflags */
#define HUSH_TF_REQUEUED (1U << 0)	/* left the CPU still runnable */
#define HUSH_TF_GUARDED (1U << 1)	/* running a starvation-guard slice */

/* cpu_ctx, per-CPU (§10.3). cur_class is u32 so it can be cmpxchg'd. */
struct cpu_ctx {
	u32 cur_class;		/* effective class of the running task */
	u32 cur_tid;
	u64 run_start;
	u64 last_guard;		/* last time this CPU granted a guard slice */
};

/* stats map, per-CPU, summed by hushd (FR-17). */
struct hush_stats {
	u64 runtime_ns[HUSH_NR_CLASSES];
	u64 wait_ns[HUSH_NR_CLASSES];
	u64 wait_max_ns[HUSH_NR_CLASSES];
	u64 nr_runs[HUSH_NR_CLASSES];
	u64 preempt_kicks;	/* BG CPUs kicked for FG/NORMAL (§7.4) */
	u64 tick_yields;	/* tick backstop forced a BG task off */
	u64 guard_firings;	/* §7.5, BG_DSQ head */
	u64 guard_normal;	/* guard slices granted to starving NORMAL tasks */
	u64 hard_guard_firings;	/* watchdog safety net; should stay 0 */
	u64 boosts[HUSH_NR_BOOST_SRC];
	u64 boost_renewals;
	u64 boost_promotions;	/* boosted tasks pulled out of BG_DSQ */
	u64 boost_capped;	/* boosts refused by the 10% cap */
	u64 hint_abuse;		/* §8.3 */
	u64 dstate_escapes;	/* tier 4 */
	u64 reclassify;		/* policy_gen / cgroup / exec re-classification */
};

/* trace_rb record (FR-19, §10.4). */
struct hush_trace_event {
	u64 ts_ns;
	u64 wait_ns;
	u32 pid;
	u32 tid;
	u32 cpu;
	u8 cls;
	u8 __pad[3];
	char comm[HUSH_COMM_LEN];
};

#endif /* __HUSH_INTF_H */
