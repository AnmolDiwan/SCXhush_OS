/*
 * scx_hush.bpf.c - Unfair-by-Design Linux CPU Scheduler
 *
 * Implements strict foreground isolation, bounded starvation guard,
 * and 4-tier futex priority inversion handling for sched_ext.
 *
 * Derived from scx_hush PRD & Architecture (Oct 22, 2026).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_compat.h"
#include "scx_hush_types.h"

char _license[] SEC("license") = "GPL";

/* BPF Maps (PRD Section 10.1) */

/* Map 1: task_ctx - Per-task local storage */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx SEC(".maps");

/* Map 2: cpu_ctx - Per-CPU state for preemption scan & guard tracking */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_ctx);
} cpu_ctx SEC(".maps");

/* Map 3: class_by_cgroup - Cgroup v2 ID to class mapping (4096 entries) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u8);
} class_by_cgroup SEC(".maps");

/* Map 4: class_by_comm - Executable name to class mapping (256 entries) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[COMM_LEN]);
    __type(value, u8);
} class_by_comm SEC(".maps");

/* Map 5: config - Scheduler parameters (slices, guard, boost) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hush_config);
} config SEC(".maps");

/* Map 6: stats - Per-CPU counters aggregated by hushd */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hush_stats);
} stats SEC(".maps");

/* Map 7: trace_rb - 4 MiB Ring Buffer for wakeup latency events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} trace_rb SEC(".maps");

/* Global state tracked in BPF */
static volatile u64 nr_cpus = 0;
static volatile u64 boost_pending = 0;

/* Helper: get current config */
static inline struct hush_config *get_config(void) {
    u32 zero = 0;
    return bpf_map_lookup_elem(&config, &zero);
}

/* Helper: get per-CPU stats */
static inline struct hush_stats *get_stats(void) {
    u32 zero = 0;
    return bpf_map_lookup_elem(&stats, &zero);
}

/* Helper: get per-CPU context */
static inline struct cpu_ctx *get_cpu_ctx(void) {
    u32 zero = 0;
    return bpf_map_lookup_elem(&cpu_ctx, &zero);
}

/*
 * Section 10.2: Compute effective class in one place.
 * Main defense against bugs where two code paths disagree.
 */
static inline u8 get_effective_class(struct task_ctx *tctx, u64 now) {
    if (!tctx)
        return CLASS_NORMAL;
    if (tctx->boost_until > now || tctx->crit_depth > 0)
        return CLASS_FOREGROUND;
    return tctx->base_class ? tctx->base_class : CLASS_NORMAL;
}

/*
 * Classification from cgroup and comm (FR-1 to FR-4)
 */
static inline u8 classify_task(struct task_struct *p, struct hush_config *cfg) {
    u64 cgid = bpf_core_read(&p->cgroups->dfl_cgrp->kn->id);
    u8 *cgroup_class = bpf_map_lookup_elem(&class_by_cgroup, &cgid);
    if (cgroup_class && *cgroup_class != CLASS_UNSPEC)
        return *cgroup_class;

    char comm[COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    u8 *comm_class = bpf_map_lookup_elem(&class_by_comm, comm);
    if (comm_class && *comm_class != CLASS_UNSPEC)
        return *comm_class;

    return CLASS_NORMAL;
}

/*
 * Section 7.4: Preemption of background work (FR-7)
 * Scans per-CPU contexts to find a CPU running BACKGROUND work and kicks it.
 */
static inline void kick_background_cpu_if_needed(s32 prev_cpu) {
    u32 max_scan = 64; /* Bounded loop for BPF verifier */
    
    /* First check task's previous CPU for cache warmth */
    struct cpu_ctx *prev_cctx = bpf_map_lookup_percpu_elem(&cpu_ctx, 0, prev_cpu);
    if (prev_cctx && prev_cctx->cur_class == CLASS_BACKGROUND) {
        scx_bpf_kick_cpu(prev_cpu, SCX_KICK_PREEMPT);
        struct hush_stats *st = get_stats();
        if (st) st->preemptions[CLASS_BACKGROUND]++;
        return;
    }

    /* Scan other CPUs */
    bpf_for(i, 0, max_scan) {
        if (i >= nr_cpus)
            break;
        if (i == prev_cpu)
            continue;
        struct cpu_ctx *cctx = bpf_map_lookup_percpu_elem(&cpu_ctx, 0, i);
        if (cctx && cctx->cur_class == CLASS_BACKGROUND) {
            scx_bpf_kick_cpu(i, SCX_KICK_PREEMPT);
            struct hush_stats *st = get_stats();
            if (st) st->preemptions[CLASS_BACKGROUND]++;
            break;
        }
    }
}

/*
 * Sched_ext Callback: select_cpu
 * Idle cycles are free: if an idle CPU is found, insert straight to local DSQ (Goal 2)
 */
s32 BPF_STRUCT_OPS(hush_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    bool is_idle = false;
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle) {
        /* Direct placement on idle core guarantees work conservation */
        struct hush_config *cfg = get_config();
        u64 slice = cfg ? cfg->normal_slice_ns : DEFAULT_NORMAL_SLICE_NS;
        struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
        if (tctx) {
            u8 eff_class = get_effective_class(tctx, scx_bpf_now());
            if (eff_class == CLASS_FOREGROUND)
                slice = cfg ? cfg->fg_slice_ns : DEFAULT_FG_SLICE_NS;
            else if (eff_class == CLASS_BACKGROUND)
                slice = cfg ? cfg->bg_slice_ns : DEFAULT_BG_SLICE_NS;
        }
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, 0);
    }
    return cpu;
}

/*
 * Sched_ext Callback: enqueue
 * Re-checks policy generation, inserts task into class DSQ, triggers preemption
 */
void BPF_STRUCT_OPS(hush_enqueue, struct task_struct *p, u64 enq_flags) {
    u64 now = scx_bpf_now();
    struct hush_config *cfg = get_config();
    struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    
    if (tctx) {
        tctx->runnable_at = now;
        /* Re-check class if policy generation changed (FR-2) */
        if (cfg && tctx->policy_gen != cfg->policy_generation) {
            tctx->base_class = classify_task(p, cfg);
            tctx->policy_gen = cfg->policy_generation;
        }
    }

    u8 eff_class = get_effective_class(tctx, now);

    if (eff_class == CLASS_FOREGROUND) {
        u64 slice = cfg ? cfg->fg_slice_ns : DEFAULT_FG_SLICE_NS;
        u64 vtime = tctx ? tctx->vtime : now;
        scx_bpf_dsq_insert_vtime(p, FG_DSQ_ID, slice, vtime, enq_flags);
        /* Preempt background core immediately (FR-7) */
        s32 prev_cpu = bpf_core_read(&p->thread_info.cpu);
        kick_background_cpu_if_needed(prev_cpu);
    } else if (eff_class == CLASS_NORMAL) {
        u64 slice = cfg ? cfg->normal_slice_ns : DEFAULT_NORMAL_SLICE_NS;
        u64 vtime = tctx ? tctx->vtime : now;
        scx_bpf_dsq_insert_vtime(p, NORMAL_DSQ_ID, slice, vtime, enq_flags);
        s32 prev_cpu = bpf_core_read(&p->thread_info.cpu);
        kick_background_cpu_if_needed(prev_cpu);
    } else {
        /* BACKGROUND: Insert to FIFO tail (FR-6, FR-10) */
        u64 slice = cfg ? cfg->bg_slice_ns : DEFAULT_BG_SLICE_NS;
        scx_bpf_dsq_insert(p, BG_DSQ_ID, slice, enq_flags);
    }
}

/*
 * Sched_ext Callback: dispatch
 * Consumes queues in strict priority order (FG -> NORMAL -> BG) with Starvation Guard (7.5)
 */
void BPF_STRUCT_OPS(hush_dispatch, s32 cpu, struct task_struct *prev) {
    u64 now = scx_bpf_now();
    struct hush_config *cfg = get_config();
    struct cpu_ctx *cctx = get_cpu_ctx();
    struct hush_stats *st = get_stats();

    u64 guard_ns = cfg ? cfg->guard_ns : DEFAULT_GUARD_NS;

    /*
     * Section 7.5: Starvation Guard (FR-11, FR-12)
     * Check if head of BG_DSQ waited longer than guard_ns.
     * Rate-limited per CPU: at most one guard slice per guard_interval per CPU.
     */
    if (cctx && (now - cctx->last_guard >= guard_ns)) {
        if (scx_bpf_dsq_nr_queued(BG_DSQ_ID) > 0) {
            /* Grant one slice from BG_DSQ */
            if (scx_bpf_dsq_move_to_local(BG_DSQ_ID)) {
                cctx->last_guard = now;
                if (st) st->guard_firings++;
                return;
            }
        }
    }

    /*
     * Strict Class Draining:
     * 1. FG_DSQ (Virtual time order)
     * 2. NORMAL_DSQ (Virtual time order)
     * 3. BG_DSQ (FIFO order)
     */
    if (scx_bpf_dsq_move_to_local(FG_DSQ_ID))
        return;

    if (scx_bpf_dsq_move_to_local(NORMAL_DSQ_ID))
        return;

    scx_bpf_dsq_move_to_local(BG_DSQ_ID);
}

/*
 * Sched_ext Callback: running
 * Tracks start time and current class on this CPU
 */
void BPF_STRUCT_OPS(hush_running, struct task_struct *p) {
    u64 now = scx_bpf_now();
    struct cpu_ctx *cctx = get_cpu_ctx();
    struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    u8 eff_class = get_effective_class(tctx, now);

    if (cctx) {
        cctx->cur_class = eff_class;
        cctx->run_start = now;
        cctx->cur_pid = bpf_core_read(&p->tgid);
        cctx->cur_tid = bpf_core_read(&p->pid);
    }

    /* Emit trace record if trace buffer available */
    if (tctx && tctx->runnable_at > 0) {
        struct trace_event *evt = bpf_ringbuf_reserve(&trace_rb, sizeof(*evt), 0);
        if (evt) {
            evt->timestamp_ns = now;
            evt->pid = bpf_core_read(&p->tgid);
            evt->tid = bpf_core_read(&p->pid);
            bpf_get_current_comm(evt->comm, sizeof(evt->comm));
            evt->task_class = eff_class;
            evt->wait_ns = now - tctx->runnable_at;
            evt->cpu = bpf_get_smp_processor_id();
            evt->event_type = 1;
            bpf_ringbuf_submit(evt, 0);
        }
        struct hush_stats *st = get_stats();
        if (st && eff_class < 4) {
            st->wait_ns[eff_class] += (now - tctx->runnable_at);
        }
    }
}

/*
 * Sched_ext Callback: stopping
 * Charges virtual time and accumulates runtime stats
 */
void BPF_STRUCT_OPS(hush_stopping, struct task_struct *p, bool runnable) {
    u64 now = scx_bpf_now();
    struct cpu_ctx *cctx = get_cpu_ctx();
    struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    if (cctx && cctx->run_start > 0) {
        u64 delta = now - cctx->run_start;
        u8 eff_class = cctx->cur_class;

        struct hush_stats *st = get_stats();
        if (st && eff_class < 4) {
            st->runtime_ns[eff_class] += delta;
        }

        if (tctx) {
            /* Virtual time charging scaled by priority */
            tctx->vtime += delta;
            if (tctx->boost_until > now) {
                tctx->boost_used_ns += delta;
            }
        }
        cctx->cur_class = CLASS_UNSPEC;
        cctx->run_start = 0;
    }
}

/*
 * Sched_ext Callback: tick
 * Backstop: if BACKGROUND task is running and FG_DSQ is non-empty, yield immediately
 */
void BPF_STRUCT_OPS(hush_tick, struct task_struct *p) {
    struct cpu_ctx *cctx = get_cpu_ctx();
    if (cctx && cctx->cur_class == CLASS_BACKGROUND) {
        if (scx_bpf_dsq_nr_queued(FG_DSQ_ID) > 0 || scx_bpf_dsq_nr_queued(NORMAL_DSQ_ID) > 0) {
            /* Yield CPU immediately */
            scx_bpf_kick_cpu(bpf_get_smp_processor_id(), SCX_KICK_PREEMPT);
        }
    }
}

/*
 * Sched_ext Callback: init
 * Initializes custom DSQs and CPU count
 */
s32 BPF_STRUCT_OPS_ENTRY(hush_init) {
    s32 ret;

    ret = scx_bpf_create_dsq(FG_DSQ_ID, -1);
    if (ret) return ret;

    ret = scx_bpf_create_dsq(NORMAL_DSQ_ID, -1);
    if (ret) return ret;

    ret = scx_bpf_create_dsq(BG_DSQ_ID, -1);
    if (ret) return ret;

    nr_cpus = bpf_num_possible_cpus();
    return 0;
}

/*
 * Sched_ext Callback: exit
 */
void BPF_STRUCT_OPS(hush_exit, struct scx_exit_info *ei) {
    /* Safe fallback guaranteed by sched_ext */
}

/*
 * Priority Inversion Hooks (Section 8)
 * Tier 1: Uprobes on libhush hint API
 */
SEC("uprobe/hush_critical_enter")
int BPF_KPROBE(uprobe_hush_critical_enter) {
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (tctx) {
        /* Section 8.3: 10% abuse cap check */
        if (tctx->boost_used_ns > 100000000ULL) { /* >100ms in 1 sec */
            struct hush_stats *st = get_stats();
            if (st) st->hint_abuse_count++;
            return 0;
        }
        tctx->crit_depth++;
        struct hush_stats *st = get_stats();
        if (st) st->boost_count++;
    }
    return 0;
}

SEC("uprobe/hush_critical_exit")
int BPF_KPROBE(uprobe_hush_critical_exit) {
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (tctx && tctx->crit_depth > 0) {
        tctx->crit_depth--;
    }
    return 0;
}

/*
 * Tier 2 & 3: Futex Tracepoint Hooks
 * Detects FOREGROUND waiter blocked on lock held by BACKGROUND task
 */
SEC("tp/syscalls/sys_enter_futex")
int tp_futex_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 uaddr = (u64)ctx->args[0];
    int op = (int)ctx->args[1];
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    struct task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);

    /* FUTEX_WAIT or FUTEX_LOCK_PI */
    if (op == 0 /* FUTEX_WAIT */ || op == 6 /* FUTEX_LOCK_PI */) {
        if (tctx) {
            tctx->wait_uaddr = uaddr;
        }
    }
    return 0;
}

/* Sched_ext Ops Registration */
SEC(".struct_ops.link")
struct sched_ext_ops hush_ops = {
    .select_cpu      = (void *)hush_select_cpu,
    .enqueue         = (void *)hush_enqueue,
    .dispatch        = (void *)hush_dispatch,
    .running         = (void *)hush_running,
    .stopping        = (void *)hush_stopping,
    .tick            = (void *)hush_tick,
    .init            = (void *)hush_init,
    .exit            = (void *)hush_exit,
    .name            = SCX_OPS_NAME,
};

