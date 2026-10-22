#ifndef SCX_HUSH_TYPES_H
#define SCX_HUSH_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Task Classification according to FR-1 */
typedef enum {
    CLASS_UNSPEC     = 0,
    CLASS_FOREGROUND = 1,
    CLASS_NORMAL     = 2,
    CLASS_BACKGROUND = 3
} task_class_t;

/* Dispatch Queue IDs (Section 7.2) */
#define FG_DSQ_ID     1ULL
#define NORMAL_DSQ_ID 2ULL
#define BG_DSQ_ID     3ULL

/* Constants and Defaults */
#define DEFAULT_FG_SLICE_NS      5000000ULL   /* 5 ms */
#define DEFAULT_NORMAL_SLICE_NS 10000000ULL  /* 10 ms */
#define DEFAULT_BG_SLICE_NS     20000000ULL  /* 20 ms */
#define DEFAULT_GUARD_NS      2000000000ULL  /* 2000 ms (2 s) */
#define DEFAULT_BOOST_NS        50000000ULL  /* 50 ms */
#define DEFAULT_BOOST_CAP_PCT   10           /* 10% runtime per sec */
#define DEFAULT_WATCHDOG_NS   8000000000ULL  /* 8000 ms (8 s) */

#define COMM_LEN 16

/* Per-task state: Section 10.2 (task_ctx) */
struct task_ctx {
    uint8_t   base_class;     /* Class from policy: FG, NORMAL, or BG */
    uint32_t  policy_gen;     /* Policy gen when classified */
    uint64_t  boost_until;    /* Effective class is FG while now < boost_until */
    uint64_t  boost_used_ns;  /* Cumulative boost time in current second */
    uint16_t  crit_depth;     /* Nesting depth of hush_critical_enter */
    uint64_t  runnable_at;    /* Timestamp when task last became runnable */
    uint64_t  vtime;          /* Weighted virtual time within class */
    uint64_t  wait_uaddr;     /* Futex address this task is blocked on */
    uint32_t  flags;          /* Flags: e.g. pinned, D-state, etc. */
};

/* Per-CPU state: Section 10.3 (cpu_ctx) */
struct cpu_ctx {
    uint8_t   cur_class;      /* Current class executing on this CPU */
    uint64_t  run_start;      /* Timestamp when current task started running */
    uint64_t  last_guard;     /* Timestamp when last guard slice was granted */
    uint32_t  cur_pid;        /* PID currently running */
    uint32_t  cur_tid;        /* TID currently running */
};

/* Global Scheduler Configuration: Section 10.1 (config map) */
struct hush_config {
    uint64_t  fg_slice_ns;
    uint64_t  normal_slice_ns;
    uint64_t  bg_slice_ns;
    uint64_t  guard_ns;
    uint64_t  boost_ns;
    uint32_t  boost_cap_pct;
    uint32_t  policy_generation;
    uint64_t  watchdog_timeout_ns;
};

/* Per-class and scheduler-wide metrics: Section 10.1 (stats) */
struct hush_stats {
    uint64_t  runtime_ns[4];     /* Index by task_class_t */
    uint64_t  wait_ns[4];        /* Total wait time accumulated */
    uint64_t  preemptions[4];    /* Number of preemptions triggered */
    uint64_t  tasks_completed[4];
    uint64_t  guard_firings;     /* Starvation guard interventions */
    uint64_t  boost_count;       /* Inversion boosts granted */
    uint64_t  hint_abuse_count;  /* Hints rejected due to 10% cap */
    uint64_t  dstate_escapes;    /* Tier 4 D-state escape activations */
};

/* Trace record emitted to trace_rb: Section 10.1 */
struct trace_event {
    uint64_t  timestamp_ns;
    uint32_t  pid;
    uint32_t  tid;
    char      comm[COMM_LEN];
    uint8_t   task_class;
    uint64_t  wait_ns;
    uint32_t  cpu;
    uint8_t   event_type;        /* 1: Wakeup/dispatch, 2: Preempt, 3: Guard, 4: Boost */
};

/* Helper: Effective class computation (Section 10.2) */
static inline uint8_t scx_hush_effective_class(const struct task_ctx *ctx, uint64_t now) {
    if (!ctx) return CLASS_NORMAL;
    if (ctx->boost_until > now || ctx->crit_depth > 0) {
        return CLASS_FOREGROUND;
    }
    return ctx->base_class ? ctx->base_class : CLASS_NORMAL;
}

#ifdef __cplusplus
}
#endif

#endif /* SCX_HUSH_TYPES_H */

