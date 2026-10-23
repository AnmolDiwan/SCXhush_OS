/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_hush - an unfair-by-design sched_ext scheduler.
 *
 * Background (BG) tasks run only on CPU time that foreground (FG) and
 * unclassified (NORMAL) tasks leave idle. Three custom DSQs are drained in
 * strict class order; a waking FG/NORMAL task kicks a CPU that is running BG
 * work; a per-CPU rate-limited starvation guard bounds how long queued work
 * can wait; lock holders that block FG work are temporarily boosted to FG.
 *
 * Section numbers (§x.y) refer to the scx_hush PRD & Architecture document.
 * All sched_ext API names live in hush_compat.bpf.h (NFR-9).
 */
#include "hush_compat.bpf.h"
#include "hush_intf.h"

char _license[] SEC("license") = "GPL";

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif
#define TASK_UNINTERRUPTIBLE_BIT 0x0002
#define TASK_NOLOAD_BIT 0x0400

/* futex(2) ABI, include/uapi/linux/futex.h */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_LOCK_PI2 13
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_CMD_MASK (~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME))
#define FUTEX_TID_MASK 0x3fffffff

#if defined(__TARGET_ARCH_x86)
#define HUSH_NR_futex 202
#elif defined(__TARGET_ARCH_arm64)
#define HUSH_NR_futex 98
#else
#error "unsupported architecture (NFR-7 covers x86-64 and arm64)"
#endif

/* glibc struct __pthread_mutex_s: __lock (futex word) then __count, __owner. */
#define GLIBC_MUTEX_OWNER_OFF 8

#define RECENT_BG_SLOTS 4

/* Set by hushd before load. */
const volatile u32 nr_cpus = 1;

/* Per-class virtual-time frontier for FG_DSQ and NORMAL_DSQ (§7.6). */
u64 vtime_now[HUSH_NR_CLASSES];
/* Boosted holders that may still sit in BG_DSQ (§8.2 step 2). */
u64 boost_pending;
/* Tier 4: FG tasks in uninterruptible sleep and the escape window. */
s64 fg_dstate_nr;
u64 fg_dstate_since;
u64 escape_until;

HUSH_UEI_DEFINE(uei);

/* ------------------------------------------------------------------ maps */

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cpu_ctx);
} cpu_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HUSH_MAP_CGROUP_MAX);
	__type(key, u64);
	__type(value, u8);
} class_by_cgroup SEC(".maps");

struct comm_key {
	char comm[HUSH_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HUSH_MAP_COMM_MAX);
	__type(key, struct comm_key);
	__type(value, u8);
} class_by_comm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HUSH_MAP_UID_MAX);
	__type(key, u32);
	__type(value, u8);
} class_by_uid SEC(".maps");

/* hushctl promote/demote <pid>, keyed by tgid. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, HUSH_MAP_PID_MAX);
	__type(key, u32);
	__type(value, u8);
} class_by_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hush_config);
} hush_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct hush_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} trace_rb SEC(".maps");

/* Same-process fallback (§8.1): BG threads of a process that ran recently. */
struct recent_bg {
	u32 tid[RECENT_BG_SLOTS];
	u64 ts[RECENT_BG_SLOTS];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u32);
	__type(value, struct recent_bg);
} recent_bg SEC(".maps");

/* --------------------------------------------------------------- helpers */

/*
 * One clock for everything. Hook programs of kprobe type cannot call
 * scx_bpf_now(), and boost deadlines written there are compared in the
 * scheduler callbacks, so every timestamp uses the same monotonic clock.
 */
static __always_inline u64 now_ns(void)
{
	return bpf_ktime_get_ns();
}

static __always_inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static __always_inline struct hush_config *cfg_get(void)
{
	u32 zero = 0;

	return bpf_map_lookup_elem(&hush_cfg, &zero);
}

static __always_inline struct hush_stats *stats_get(void)
{
	u32 zero = 0;

	return bpf_map_lookup_elem(&stats, &zero);
}

static __always_inline struct cpu_ctx *cpu_ctx_get(void)
{
	u32 zero = 0;

	return bpf_map_lookup_elem(&cpu_ctx, &zero);
}

static __always_inline struct cpu_ctx *cpu_ctx_of(s32 cpu)
{
	u32 zero = 0;

	return bpf_map_lookup_percpu_elem(&cpu_ctx, &zero, cpu);
}

static __always_inline struct task_ctx *tctx_get(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx, p, 0, 0);
}

static __always_inline u64 slice_for(struct hush_config *cfg, u8 cls)
{
	u64 s = cfg ? cfg->slice_ns[cls & (HUSH_NR_CLASSES - 1)] : 0;

	if (s)
		return s;
	if (cls == HUSH_CLASS_FG)
		return HUSH_DFL_FG_SLICE_NS;
	if (cls == HUSH_CLASS_BG)
		return HUSH_DFL_BG_SLICE_NS;
	return HUSH_DFL_NORMAL_SLICE_NS;
}

static __always_inline u32 cfg_flags(struct hush_config *cfg)
{
	return cfg ? cfg->flags : 0;
}

static __always_inline u32 cpu_bound(void)
{
	return nr_cpus < HUSH_MAX_CPUS ? nr_cpus : HUSH_MAX_CPUS;
}

static __always_inline u64 task_cgid(struct task_struct *p)
{
	return BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
}

/*
 * §8.3: boosted runtime is capped at boost_cap_pct of each 1 s window. The
 * cap covers every boost source so no path can pin a BG task at FG forever.
 */
static __always_inline bool boost_allowed(struct task_ctx *t,
					  struct hush_config *cfg, u64 now)
{
	u64 cap_pct = cfg && cfg->boost_cap_pct ? cfg->boost_cap_pct :
						  HUSH_DFL_BOOST_CAP_PCT;

	if (now - t->boost_win_start >= HUSH_BOOST_WINDOW_NS)
		return true;
	return t->boost_used_ns < HUSH_BOOST_WINDOW_NS / 100 * cap_pct;
}

/*
 * §10.2: the single place that decides a task's effective class. Every
 * callback goes through here so no two paths can disagree.
 */
static __always_inline u8 effective_class(struct task_ctx *t,
					  struct hush_config *cfg, u64 now)
{
	u8 base = t->base_class ? t->base_class : HUSH_CLASS_NORMAL;

	if (base != HUSH_CLASS_FG && boost_allowed(t, cfg, now)) {
		if (t->boost_until > now)
			return HUSH_CLASS_FG;
		if (t->crit_depth && (cfg_flags(cfg) & HUSH_F_HINTS))
			return HUSH_CLASS_FG;
	}
	/* Tier 4 escape window: BG temporarily runs as NORMAL. */
	if (base == HUSH_CLASS_BG && escape_until > now)
		return HUSH_CLASS_NORMAL;
	return base;
}

/* FR-1..FR-4 and §7.7: resolve a task's base class from policy maps. */
static __always_inline u8 resolve_class(struct task_struct *p,
					struct task_ctx *t, u64 cgid)
{
	struct comm_key key;
	u32 id;
	u8 *c;

	if (BPF_CORE_READ(p, flags) & PF_KTHREAD) {
		t->reason = HUSH_RSN_KTHREAD;
		return HUSH_CLASS_NORMAL;
	}

	id = BPF_CORE_READ(p, tgid);
	c = bpf_map_lookup_elem(&class_by_pid, &id);
	if (c && *c) {
		t->reason = HUSH_RSN_PID;
		return *c;
	}

	c = bpf_map_lookup_elem(&class_by_cgroup, &cgid);
	if (c && *c) {
		t->reason = HUSH_RSN_CGROUP;
		return *c;
	}

	__builtin_memset(&key, 0, sizeof(key));
	bpf_probe_read_kernel_str(key.comm, sizeof(key.comm), p->comm);
	c = bpf_map_lookup_elem(&class_by_comm, &key);
	if (c && *c) {
		t->reason = HUSH_RSN_COMM;
		return *c;
	}

	id = BPF_CORE_READ(p, cred, uid.val);
	c = bpf_map_lookup_elem(&class_by_uid, &id);
	if (c && *c) {
		t->reason = HUSH_RSN_UID;
		return *c;
	}

	if (t->inherit_class) {
		t->reason = HUSH_RSN_INHERIT;
		return t->inherit_class;
	}

	t->reason = HUSH_RSN_DEFAULT;
	return HUSH_CLASS_NORMAL;
}

static __always_inline void classify(struct task_struct *p, struct task_ctx *t,
				     struct hush_config *cfg, u64 cgid)
{
	struct hush_stats *st = stats_get();
	u8 cls = resolve_class(p, t, cgid);

	if (cls >= HUSH_NR_CLASSES)
		cls = HUSH_CLASS_NORMAL;
	t->base_class = cls;
	t->cgid = cgid;
	t->policy_gen = cfg ? cfg->policy_gen : 0;
	if (st)
		st->reclassify++;
}

/*
 * Re-classify when the policy generation moved (reload, promote, demote),
 * the task changed cgroup, or it exec'd (the exec hook zeroes policy_gen).
 */
static __always_inline void refresh_class(struct task_struct *p,
					  struct task_ctx *t,
					  struct hush_config *cfg)
{
	u64 cgid = task_cgid(p);

	if (!cfg || t->policy_gen != cfg->policy_gen || t->cgid != cgid)
		classify(p, t, cfg, cgid);
}

/* §7.6: weighted virtual time within FG_DSQ / NORMAL_DSQ. */
static __always_inline u64 task_vtime(struct task_struct *p,
				      struct task_ctx *t, u8 cls, u64 slice)
{
	u64 vnow = vtime_now[cls & (HUSH_NR_CLASSES - 1)];
	u64 vt = p->scx.dsq_vtime;

	/*
	 * A task changing class carries a vtime from another queue's frame;
	 * start it at this class's frontier. Otherwise clamp sleepers to one
	 * slice behind the frontier so they cannot monopolise the CPU.
	 */
	if (t->last_class != cls)
		vt = vnow;
	else if (vtime_before(vt, vnow - slice))
		vt = vnow - slice;
	p->scx.dsq_vtime = vt;
	t->last_class = cls;
	return vt;
}

/*
 * §7.4: find a CPU running BACKGROUND work, starting at @p's previous CPU
 * for cache warmth, and preempt it. Bounded by the CPU count. The cmpxchg
 * claims the CPU so concurrent wakers do not all kick the same one.
 */
static bool preempt_bg_cpu(struct task_struct *p)
{
	struct hush_stats *st;
	u32 n = cpu_bound();
	s32 start = hush_task_cpu(p);
	u32 i;

	if (escape_until > now_ns())
		return false;

	bpf_for(i, 0, n) {
		s32 cpu = start + i;
		struct cpu_ctx *cc;

		if (cpu >= (s32)n)
			cpu -= n;
		if (cpu < 0 || cpu >= (s32)n)
			continue;
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		cc = cpu_ctx_of(cpu);
		if (!cc || cc->cur_class != HUSH_CLASS_BG)
			continue;
		if (__sync_val_compare_and_swap(&cc->cur_class, HUSH_CLASS_BG,
						HUSH_CLASS_NONE) != HUSH_CLASS_BG)
			continue;
		hush_kick_preempt(cpu);
		st = stats_get();
		if (st)
			st->preempt_kicks++;
		return true;
	}
	return false;
}

/*
 * §8.2 step 1: boost a lock holder that blocks a FOREGROUND waiter. Runs in
 * the waiter's context (futex hook) or the holder's (renewal).
 */
static void boost_task(struct task_struct *holder, u64 uaddr, u32 waiter_tid,
		       u8 src, struct hush_config *cfg)
{
	struct hush_stats *st = stats_get();
	u64 now = now_ns();
	struct task_ctx *h = tctx_get(holder);
	struct cpu_ctx *cc;
	bool active;
	s32 cpu;

	if (!h || h->base_class == HUSH_CLASS_FG || !cfg)
		return;
	if (!boost_allowed(h, cfg, now)) {
		if (st)
			st->boost_capped++;
		return;
	}

	active = h->boost_until > now;
	h->boost_until = now + (cfg->boost_ns ? cfg->boost_ns : HUSH_DFL_BOOST_NS);
	h->boost_uaddr = uaddr;
	h->boost_waiter = waiter_tid;
	h->boost_src = src;
	if (active)
		return;

	if (st)
		st->boosts[src & (HUSH_NR_BOOST_SRC - 1)]++;

	/* If the holder is on a CPU, stop the preemption scan from kicking it. */
	cpu = hush_task_cpu(holder);
	cc = cpu_ctx_of(cpu);
	if (cc && cc->cur_tid == BPF_CORE_READ(holder, pid)) {
		cc->cur_class = HUSH_CLASS_FG;
		return;
	}

	/* Otherwise it is queued, most likely in BG_DSQ: let dispatch pull it. */
	__sync_fetch_and_add(&boost_pending, 1);
	preempt_bg_cpu(holder);
}

/* §8.2 step 4: renew an expired boost only while the waiter still waits. */
static void maybe_renew_boost(struct task_ctx *h, struct hush_config *cfg,
			      u64 now)
{
	struct task_struct *w;
	struct task_ctx *wt;
	struct hush_stats *st;

	if (!h->boost_waiter || h->boost_until > now || !cfg)
		return;

	w = hush_task_from_tid(h->boost_waiter);
	if (!w) {
		h->boost_waiter = 0;
		return;
	}
	wt = tctx_get(w);
	if (wt && wt->wait_uaddr && wt->wait_uaddr == h->boost_uaddr &&
	    boost_allowed(h, cfg, now)) {
		h->boost_until = now + (cfg->boost_ns ? cfg->boost_ns :
							HUSH_DFL_BOOST_NS);
		st = stats_get();
		if (st)
			st->boost_renewals++;
	} else {
		h->boost_waiter = 0;
	}
	hush_task_release(w);
}

/* Charge time spent boosted against the §8.3 cap window. */
static __always_inline void charge_boost(struct task_ctx *t, u64 used, u64 now)
{
	if (now - t->boost_win_start >= HUSH_BOOST_WINDOW_NS) {
		t->boost_win_start = now;
		t->boost_used_ns = 0;
	}
	t->boost_used_ns += used;
}

static __always_inline void note_recent_bg(struct task_struct *p, u64 now)
{
	u32 tgid = BPF_CORE_READ(p, tgid), tid = BPF_CORE_READ(p, pid);
	struct recent_bg *r, init = {};
	u32 i, slot = 0;
	u64 oldest = ~0ULL;

	r = bpf_map_lookup_elem(&recent_bg, &tgid);
	if (!r) {
		init.tid[0] = tid;
		init.ts[0] = now;
		bpf_map_update_elem(&recent_bg, &tgid, &init, BPF_NOEXIST);
		return;
	}
	bpf_for(i, 0, RECENT_BG_SLOTS) {
		if (r->tid[i] == tid) {
			slot = i;
			break;
		}
		if (r->ts[i] < oldest) {
			oldest = r->ts[i];
			slot = i;
		}
	}
	if (slot < RECENT_BG_SLOTS) {
		r->tid[slot] = tid;
		r->ts[slot] = now;
	}
}

/* ---------------------------------------------------- dispatch helpers */

/*
 * §8.2 step 2: hook programs cannot move tasks between DSQs, so the next
 * dispatch on any CPU walks the head of BG_DSQ and pulls boosted tasks out.
 * The first one that can run here goes to the local DSQ; others go to
 * FG_DSQ at the FG frontier.
 */
static bool promote_boosted(s32 cpu, struct hush_config *cfg, u64 now)
{
	struct hush_stats *st = stats_get();
	struct task_struct *p;
	bool local = false;
	u32 seen = 0;

	if (!__sync_lock_test_and_set(&boost_pending, 0))
		return false;

	hush_dsq_for_each(p, HUSH_BG_DSQ) {
		struct task_ctx *t;

		if (++seen > HUSH_BOOST_WALK_MAX) {
			/* Not done: let the next dispatch keep going. */
			__sync_fetch_and_add(&boost_pending, 1);
			break;
		}
		t = tctx_get(p);
		if (!t || effective_class(t, cfg, now) != HUSH_CLASS_FG)
			continue;

		if (!local && bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			hush_dsq_move_set_slice(HUSH_DSQ_ITER,
						slice_for(cfg, HUSH_CLASS_FG));
			if (hush_dsq_move(HUSH_DSQ_ITER, p, HUSH_DSQ_LOCAL)) {
				local = true;
				t->last_class = HUSH_CLASS_FG;
				if (st)
					st->boost_promotions++;
			}
			continue;
		}

		hush_dsq_move_set_slice(HUSH_DSQ_ITER, slice_for(cfg, HUSH_CLASS_FG));
		hush_dsq_move_set_vtime(HUSH_DSQ_ITER, vtime_now[HUSH_CLASS_FG]);
		if (hush_dsq_move_vtime(HUSH_DSQ_ITER, p, HUSH_FG_DSQ)) {
			t->last_class = HUSH_CLASS_FG;
			if (st)
				st->boost_promotions++;
		}
	}
	return local;
}

/*
 * §7.5 starvation guard on the head of @dsq. Rate-limited to one slice per
 * CPU per guard interval. The hard guard (head older than watchdog/2) skips
 * the rate limit: without it, many more BG tasks than CPUs could keep the
 * FIFO tail waiting past the watchdog and get the scheduler ejected.
 */
static bool guard_dsq(u64 dsq, s32 cpu, struct cpu_ctx *cc,
		      struct hush_config *cfg, u64 now)
{
	u64 guard = cfg && cfg->guard_ns ? cfg->guard_ns : HUSH_DFL_GUARD_NS;
	u64 hard = cfg && cfg->hard_guard_ns ? cfg->hard_guard_ns :
					       HUSH_DFL_WATCHDOG_MS * 1000000ULL / 2;
	struct hush_stats *st;
	struct task_struct *p;
	bool fired = false;

	if (hush_nr_queued(dsq) <= 0)
		return false;

	hush_dsq_for_each(p, dsq) {
		struct task_ctx *t = tctx_get(p);
		u64 waited;
		bool is_hard;

		if (!t || !t->runnable_at)
			break;
		waited = now - t->runnable_at;
		is_hard = waited > hard;
		if (waited <= guard ||
		    (!is_hard && now - cc->last_guard < guard))
			break;
		/* Leave pinned heads to a CPU they can run on. */
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			break;
		if (!hush_dsq_move(HUSH_DSQ_ITER, p, HUSH_DSQ_LOCAL))
			break;

		t->tflags |= HUSH_TF_GUARDED;
		cc->last_guard = now;
		fired = true;
		st = stats_get();
		if (st) {
			if (is_hard)
				st->hard_guard_firings++;
			else if (dsq == HUSH_BG_DSQ)
				st->guard_firings++;
			else
				st->guard_normal++;
		}
		break;
	}
	return fired;
}

/* Tier 4 (FR-16): open an escape window if FG has been stuck in D state. */
static __always_inline void dstate_check(struct hush_config *cfg, u64 now)
{
	struct hush_stats *st;
	u64 thresh, win;

	if (!cfg || !(cfg->flags & HUSH_F_DSTATE) || fg_dstate_nr <= 0 ||
	    escape_until > now)
		return;
	thresh = cfg->dstate_thresh_ns ? cfg->dstate_thresh_ns :
					 HUSH_DFL_DSTATE_THRESH_NS;
	if (now - fg_dstate_since < thresh)
		return;
	win = cfg->escape_ns ? cfg->escape_ns : HUSH_DFL_ESCAPE_NS;
	escape_until = now + win;
	/* The next window needs another full threshold of D-state time. */
	fg_dstate_since = now + win;
	st = stats_get();
	if (st)
		st->dstate_escapes++;
}

/* ------------------------------------------------------ sched_ext ops */

s32 HUSH_OPS(hush_select_cpu, struct task_struct *p, s32 prev_cpu,
	     u64 wake_flags)
{
	struct hush_config *cfg;
	struct task_ctx *t;
	bool idle = false;
	u8 cls = HUSH_CLASS_NORMAL;
	s32 cpu;

	cpu = hush_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
	if (!idle)
		return cpu;

	/* Idle cycles are free: any class runs at once (goal 2). */
	cfg = cfg_get();
	t = tctx_get(p);
	if (t) {
		refresh_class(p, t, cfg);
		cls = effective_class(t, cfg, now_ns());
		if (cls != HUSH_CLASS_BG)
			task_vtime(p, t, cls, slice_for(cfg, cls));
		else
			t->last_class = cls;
	}
	hush_insert(p, HUSH_DSQ_LOCAL, slice_for(cfg, cls), 0);
	return cpu;
}

void HUSH_OPS(hush_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct hush_config *cfg = cfg_get();
	struct task_ctx *t = tctx_get(p);
	u64 now = now_ns(), slice, vt;
	bool requeued;
	u8 cls;

	if (!t) {
		slice = slice_for(cfg, HUSH_CLASS_NORMAL);
		hush_insert_vtime(p, HUSH_NORMAL_DSQ, slice,
				  vtime_now[HUSH_CLASS_NORMAL], enq_flags);
		return;
	}

	refresh_class(p, t, cfg);
	maybe_renew_boost(t, cfg, now);
	cls = effective_class(t, cfg, now);
	slice = slice_for(cfg, cls);
	requeued = t->tflags & HUSH_TF_REQUEUED;
	t->tflags &= ~HUSH_TF_REQUEUED;

	if (cls == HUSH_CLASS_BG) {
		/* FIFO tail; runs only when FG and NORMAL are empty (FR-6). */
		t->last_class = cls;
		hush_insert(p, HUSH_BG_DSQ, slice, enq_flags);
		return;
	}

	/*
	 * §7.7: pinned FG/NORMAL tasks (including per-CPU kthreads) go to
	 * their CPU's local DSQ so dispatch never has to migrate them. Pinned
	 * BG tasks stay in BG_DSQ: a local DSQ would run them ahead of FG.
	 */
	if (BPF_CORE_READ(p, nr_cpus_allowed) == 1) {
		s32 cpu = hush_task_cpu(p);
		struct cpu_ctx *cc = cpu_ctx_of(cpu);

		task_vtime(p, t, cls, slice);
		hush_insert(p, HUSH_DSQ_LOCAL_ON(cpu), slice, enq_flags);
		if (cc && cc->cur_class == HUSH_CLASS_BG &&
		    __sync_val_compare_and_swap(&cc->cur_class, HUSH_CLASS_BG,
						HUSH_CLASS_NONE) == HUSH_CLASS_BG)
			hush_kick_preempt(cpu);
		return;
	}

	vt = task_vtime(p, t, cls, slice);
	hush_insert_vtime(p, cls == HUSH_CLASS_FG ? HUSH_FG_DSQ : HUSH_NORMAL_DSQ,
			  slice, vt, enq_flags);

	/*
	 * FR-7/FR-9: a newly runnable FG or NORMAL task that found no idle CPU
	 * preempts BG work. A task that only used up its slice does not: its
	 * own CPU is about to dispatch and will pick it from FG_DSQ.
	 */
	if (!requeued)
		preempt_bg_cpu(p);
}

void HUSH_OPS(hush_dispatch, s32 cpu, struct task_struct *prev)
{
	struct hush_config *cfg = cfg_get();
	struct cpu_ctx *cc = cpu_ctx_get();
	u64 now = now_ns();

	dstate_check(cfg, now);

	if (boost_pending && promote_boosted(cpu, cfg, now))
		return;

	/* §7.5; NORMAL first so kernel threads can never starve. */
	if (cc && (guard_dsq(HUSH_NORMAL_DSQ, cpu, cc, cfg, now) ||
		   guard_dsq(HUSH_BG_DSQ, cpu, cc, cfg, now)))
		return;

	/* Strict class order, stopping at the first success. */
	if (hush_move_to_local(HUSH_FG_DSQ))
		return;
	if (hush_move_to_local(HUSH_NORMAL_DSQ))
		return;
	hush_move_to_local(HUSH_BG_DSQ);
}

void HUSH_OPS(hush_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *t = tctx_get(p);

	if (!t)
		return;
	t->runnable_at = now_ns();
	/* Woken up: no longer blocked on a futex (ends boost renewal). */
	t->wait_uaddr = 0;
	if (t->dsleep_at) {
		t->dsleep_at = 0;
		__sync_fetch_and_sub(&fg_dstate_nr, 1);
	}
}

void HUSH_OPS(hush_running, struct task_struct *p)
{
	struct hush_config *cfg = cfg_get();
	struct cpu_ctx *cc = cpu_ctx_get();
	struct task_ctx *t = tctx_get(p);
	struct hush_stats *st;
	struct hush_trace_event *ev;
	u64 now = now_ns(), wait = 0;
	u8 cls = HUSH_CLASS_NORMAL;

	if (t) {
		cls = effective_class(t, cfg, now);
		t->run_class = cls;
		if (t->runnable_at) {
			wait = now - t->runnable_at;
			t->runnable_at = 0;
		}
	}
	cls &= HUSH_NR_CLASSES - 1;

	if (cc) {
		/* Guard slices are not preemptible by the §7.4 scan. */
		cc->cur_class = t && (t->tflags & HUSH_TF_GUARDED) ?
					HUSH_CLASS_NORMAL : cls;
		cc->cur_tid = BPF_CORE_READ(p, pid);
		cc->run_start = now;
	}

	if ((cls == HUSH_CLASS_FG || cls == HUSH_CLASS_NORMAL) &&
	    vtime_before(vtime_now[cls], p->scx.dsq_vtime))
		vtime_now[cls] = p->scx.dsq_vtime;

	st = stats_get();
	if (st) {
		st->wait_ns[cls] += wait;
		if (wait > st->wait_max_ns[cls])
			st->wait_max_ns[cls] = wait;
		st->nr_runs[cls]++;
	}

	if (!(cfg_flags(cfg) & HUSH_F_TRACE) || !wait)
		return;
	ev = bpf_ringbuf_reserve(&trace_rb, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->ts_ns = now;
	ev->wait_ns = wait;
	ev->pid = BPF_CORE_READ(p, tgid);
	ev->tid = BPF_CORE_READ(p, pid);
	ev->cpu = bpf_get_smp_processor_id();
	ev->cls = cls;
	bpf_probe_read_kernel_str(ev->comm, sizeof(ev->comm), p->comm);
	bpf_ringbuf_submit(ev, 0);
}

void HUSH_OPS(hush_stopping, struct task_struct *p, bool runnable)
{
	struct hush_config *cfg = cfg_get();
	struct cpu_ctx *cc = cpu_ctx_get();
	struct task_ctx *t = tctx_get(p);
	struct hush_stats *st;
	u64 now = now_ns(), used = 0;
	u8 cls = HUSH_CLASS_NORMAL;

	if (cc) {
		if (cc->run_start)
			used = now - cc->run_start;
		cc->cur_class = HUSH_CLASS_NONE;
		cc->cur_tid = 0;
		cc->run_start = 0;
	}
	if (t)
		cls = t->run_class & (HUSH_NR_CLASSES - 1);

	st = stats_get();
	if (st)
		st->runtime_ns[cls] += used;

	/* §7.6: charge used time, scaled inversely by weight (nice). */
	if ((cls == HUSH_CLASS_FG || cls == HUSH_CLASS_NORMAL) && p->scx.weight)
		p->scx.dsq_vtime += used * 100 / p->scx.weight;

	if (!t)
		return;
	if (cls == HUSH_CLASS_FG && t->base_class != HUSH_CLASS_FG)
		charge_boost(t, used, now);
	if (t->base_class == HUSH_CLASS_BG && (cfg_flags(cfg) & HUSH_F_FALLBACK))
		note_recent_bg(p, now);

	t->tflags &= ~HUSH_TF_GUARDED;
	if (runnable) {
		/* Still runnable (slice expired or preempted): waiting again. */
		t->runnable_at = now;
		t->tflags |= HUSH_TF_REQUEUED;
	}
}

void HUSH_OPS(hush_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct hush_config *cfg = cfg_get();
	struct task_ctx *t;
	u32 state;
	u64 now;

	if (!(cfg_flags(cfg) & HUSH_F_DSTATE) || !(deq_flags & SCX_DEQ_SLEEP))
		return;
	t = tctx_get(p);
	if (!t || t->dsleep_at)
		return;
	now = now_ns();
	if (effective_class(t, cfg, now) != HUSH_CLASS_FG)
		return;
	state = BPF_CORE_READ(p, __state);
	if (!(state & TASK_UNINTERRUPTIBLE_BIT) || (state & TASK_NOLOAD_BIT))
		return;
	t->dsleep_at = now;
	if (__sync_fetch_and_add(&fg_dstate_nr, 1) == 0)
		fg_dstate_since = now;
}

void HUSH_OPS(hush_tick, struct task_struct *p)
{
	struct hush_config *cfg = cfg_get();
	struct cpu_ctx *cc = cpu_ctx_get();
	struct task_ctx *t = tctx_get(p);
	struct hush_stats *st;
	u64 now = now_ns();
	u8 cls;

	if (!t || !cc)
		return;

	maybe_renew_boost(t, cfg, now);
	cls = effective_class(t, cfg, now);
	/* Track boosts that began or ended while the task was on CPU. */
	if (!(t->tflags & HUSH_TF_GUARDED) && cc->cur_class != HUSH_CLASS_NONE)
		cc->cur_class = cls;

	/*
	 * Backstop for the race where a kick and a new BG dispatch cross:
	 * BG never keeps a CPU while FG or NORMAL work is queued.
	 */
	if (cls == HUSH_CLASS_BG && !(t->tflags & HUSH_TF_GUARDED) &&
	    (hush_nr_queued(HUSH_FG_DSQ) > 0 ||
	     hush_nr_queued(HUSH_NORMAL_DSQ) > 0)) {
		p->scx.slice = 0;
		st = stats_get();
		if (st)
			st->tick_yields++;
	}
}

void HUSH_OPS(hush_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now[HUSH_CLASS_NORMAL];
}

s32 HUSH_OPS_SLEEPABLE(hush_init_task, struct task_struct *p,
		       struct scx_init_task_args *args)
{
	struct hush_config *cfg = cfg_get();
	struct task_ctx *t, *parent;
	u64 cgid;

	t = bpf_task_storage_get(&task_ctx, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return -ENOMEM;

	/* FR-4: a forked child inherits its parent's base class. */
	if (args->fork) {
		parent = tctx_get(bpf_get_current_task_btf());
		if (parent)
			t->inherit_class = parent->base_class;
	}

	cgid = args->cgroup ? BPF_CORE_READ(args, cgroup, kn, id) : task_cgid(p);
	classify(p, t, cfg, cgid);
	t->last_class = HUSH_CLASS_NONE;
	return 0;
}

void HUSH_OPS(hush_exit_task, struct task_struct *p,
	      struct scx_exit_task_args *args)
{
	struct task_ctx *t = tctx_get(p);

	if (t && t->dsleep_at)
		__sync_fetch_and_sub(&fg_dstate_nr, 1);
}

s32 HUSH_OPS_SLEEPABLE(hush_init)
{
	s32 ret;

	ret = hush_create_dsq(HUSH_FG_DSQ);
	if (ret)
		return ret;
	ret = hush_create_dsq(HUSH_NORMAL_DSQ);
	if (ret)
		return ret;
	return hush_create_dsq(HUSH_BG_DSQ);
}

void HUSH_OPS(hush_exit, struct scx_exit_info *ei)
{
	HUSH_UEI_RECORD(uei, ei);
}

HUSH_OPS_DEFINE(hush_ops,
		.select_cpu = (void *)hush_select_cpu,
		.enqueue = (void *)hush_enqueue,
		.dispatch = (void *)hush_dispatch,
		.runnable = (void *)hush_runnable,
		.running = (void *)hush_running,
		.stopping = (void *)hush_stopping,
		.quiescent = (void *)hush_quiescent,
		.tick = (void *)hush_tick,
		.enable = (void *)hush_enable,
		.init_task = (void *)hush_init_task,
		.exit_task = (void *)hush_exit_task,
		.init = (void *)hush_init,
		.exit = (void *)hush_exit,
		.name = "hush");

/* --------------------------------------------- classification hooks */

/* exec changes comm (e.g. a NORMAL shell exec'ing cc1): re-classify. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(hush_exec, struct task_struct *p, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct task_ctx *t = tctx_get(p);

	if (t)
		t->policy_gen = 0;	/* hushd generations start at 1 */
	return 0;
}

/* prctl(PR_SET_NAME) / pthread_setname_np also change comm. */
SEC("tp_btf/task_rename")
int BPF_PROG(hush_rename, struct task_struct *p, const char *comm)
{
	struct task_ctx *t = tctx_get(p);

	if (t)
		t->policy_gen = 0;
	return 0;
}

/* ------------------------------------- priority inversion hooks (§8) */

/* Tier 1: hush_critical_enter()/exit() in libhush.so, attached by hushd. */
SEC("uprobe")
int BPF_UPROBE(hush_hint_enter)
{
	struct hush_config *cfg = cfg_get();
	struct task_ctx *t;
	struct cpu_ctx *cc;
	struct hush_stats *st;
	u64 now;

	if (!(cfg_flags(cfg) & HUSH_F_HINTS))
		return 0;
	/* Uprobes fire in the caller's context: a task can only mark itself. */
	t = tctx_get(bpf_get_current_task_btf());
	if (!t)
		return 0;
	if (t->crit_depth < 0xffff)
		t->crit_depth++;
	if (t->base_class == HUSH_CLASS_FG || t->crit_depth != 1)
		return 0;

	now = now_ns();
	st = stats_get();
	if (!boost_allowed(t, cfg, now)) {
		if (st)
			st->hint_abuse++;
		return 0;
	}
	if (st)
		st->boosts[HUSH_BOOST_HINT]++;
	t->boost_src = HUSH_BOOST_HINT;
	/* We are on this CPU right now; keep the scan from preempting us. */
	cc = cpu_ctx_get();
	if (cc && cc->cur_class != HUSH_CLASS_NONE)
		cc->cur_class = HUSH_CLASS_FG;
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(hush_hint_exit)
{
	struct hush_config *cfg = cfg_get();
	struct task_ctx *t = tctx_get(bpf_get_current_task_btf());
	struct cpu_ctx *cc;

	if (!t || !t->crit_depth)
		return 0;
	if (--t->crit_depth)
		return 0;
	cc = cpu_ctx_get();
	if (cc && cc->cur_class == HUSH_CLASS_FG)
		cc->cur_class = effective_class(t, cfg, now_ns());
	return 0;
}

/* Same-process fallback: boost BG threads of the waiter's process. */
static void fallback_boost(struct task_struct *cur, u64 uaddr,
			   struct hush_config *cfg, u64 now)
{
	u64 win = cfg->fallback_window_ns ? cfg->fallback_window_ns :
					    HUSH_DFL_FALLBACK_WINDOW_NS;
	u32 tgid = BPF_CORE_READ(cur, tgid), self = BPF_CORE_READ(cur, pid);
	struct recent_bg *r = bpf_map_lookup_elem(&recent_bg, &tgid);
	u32 i;

	if (!r)
		return;
	bpf_for(i, 0, RECENT_BG_SLOTS) {
		struct task_struct *h;
		u32 tid = r->tid[i];

		if (!tid || tid == self || now - r->ts[i] > win)
			continue;
		h = hush_task_from_tid(tid);
		if (!h)
			continue;
		if (BPF_CORE_READ(h, tgid) == tgid)
			boost_task(h, uaddr, self, HUSH_BOOST_FALLBACK, cfg);
		hush_task_release(h);
	}
}

/* A FOREGROUND task is about to block on @uaddr; find and boost the owner. */
static void futex_wait_enter(struct task_struct *cur, u64 uaddr, int cmd,
			     struct hush_config *cfg)
{
	struct task_struct *holder;
	struct task_ctx *w = tctx_get(cur);
	u64 now = now_ns();
	u32 owner = 0, self;
	bool pi = cmd == FUTEX_LOCK_PI || cmd == FUTEX_LOCK_PI2;
	u8 src;

	if (!w)
		return;
	w->wait_uaddr = uaddr;
	if (effective_class(w, cfg, now) != HUSH_CLASS_FG)
		return;

	self = BPF_CORE_READ(cur, pid);
	if (pi) {
		/* Tier 2: the kernel ABI keeps the owner TID in the futex word. */
		u32 val = 0;

		if (bpf_probe_read_user(&val, sizeof(val), (void *)uaddr))
			return;
		owner = val & FUTEX_TID_MASK;
		src = HUSH_BOOST_PI;
	} else if (cfg->flags & HUSH_F_TIER3) {
		/* Tier 3: glibc keeps the owner TID next to the futex word. */
		s32 val = 0;

		if (!bpf_probe_read_user(&val, sizeof(val),
					 (void *)(uaddr + GLIBC_MUTEX_OWNER_OFF)) &&
		    val > 0)
			owner = val;
		src = HUSH_BOOST_GLIBC;
	}

	if (owner && owner != self) {
		holder = hush_task_from_tid(owner);
		if (holder) {
			bool same_proc = BPF_CORE_READ(holder, tgid) ==
					 BPF_CORE_READ(cur, tgid);
			/*
			 * The owner TID comes from user memory, so a waiter could
			 * name any task. A glibc private mutex owner must be in our
			 * own process; a PI owner in our process or under our uid,
			 * so nobody can lend FOREGROUND to another user's task.
			 */
			bool ok = same_proc ||
				  (pi && BPF_CORE_READ(holder, cred, euid.val) ==
					 BPF_CORE_READ(cur, cred, euid.val));

			if (ok)
				boost_task(holder, uaddr, self, src, cfg);
			hush_task_release(holder);
			if (ok)
				return;
		}
	}

	if (!pi && (cfg->flags & HUSH_F_FALLBACK))
		fallback_boost(cur, uaddr, cfg, now);
}

/* §8.2 step 4: the holder released @uaddr, so end its boost. */
static __always_inline void futex_release(struct task_struct *cur, u64 uaddr)
{
	struct task_ctx *t = tctx_get(cur);

	if (t && t->boost_until && t->boost_uaddr == uaddr) {
		t->boost_until = 0;
		t->boost_waiter = 0;
	}
}

/*
 * Tiers 2 and 3. tp_btf (not classic tp/) because the boost path needs
 * bpf_task_from_pid() and scx_bpf_kick_cpu(). This fires on every syscall,
 * so the syscall number is checked first. hushd does not attach it for the
 * B5 ablation (--no-inversion).
 */
SEC("tp_btf/sys_enter")
int BPF_PROG(hush_sys_enter, struct pt_regs *regs, long id)
{
	struct hush_config *cfg;
	struct task_struct *cur;
	u64 uaddr;
	int cmd;

	if (id != HUSH_NR_futex)
		return 0;
	cfg = cfg_get();
	if (!cfg || !(cfg->flags & HUSH_F_INVERSION))
		return 0;

	uaddr = PT_REGS_PARM1_CORE_SYSCALL(regs);
	cmd = (int)PT_REGS_PARM2_CORE_SYSCALL(regs) & FUTEX_CMD_MASK;
	cur = bpf_get_current_task_btf();

	switch (cmd) {
	case FUTEX_WAIT:
	case FUTEX_WAIT_BITSET:
	case FUTEX_LOCK_PI:
	case FUTEX_LOCK_PI2:
		futex_wait_enter(cur, uaddr, cmd, cfg);
		break;
	case FUTEX_WAKE:
	case FUTEX_WAKE_BITSET:
	case FUTEX_UNLOCK_PI:
		futex_release(cur, uaddr);
		break;
	}
	return 0;
}
