"""
scx_hush Scheduler Simulation & Execution Engine
Implements the exact sched_ext BPF state machine, DSQs, preemption,
starvation guard, and futex priority inversion tiers from the PRD.
"""

import sys
import time
import heapq
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
import tomllib
import fnmatch

# Task Class constants (FR-1)
CLASS_UNSPEC = 0
CLASS_FOREGROUND = 1
CLASS_NORMAL = 2
CLASS_BACKGROUND = 3

CLASS_NAMES = {
    CLASS_UNSPEC: "UNSPEC",
    CLASS_FOREGROUND: "FOREGROUND",
    CLASS_NORMAL: "NORMAL",
    CLASS_BACKGROUND: "BACKGROUND",
}

# DSQ IDs
FG_DSQ_ID = 1
NORMAL_DSQ_ID = 2
BG_DSQ_ID = 3


@dataclass
class TaskCtx:
    pid: int
    tid: int
    comm: str
    cgroup: str
    base_class: int = CLASS_NORMAL
    policy_gen: int = 0
    boost_until: float = 0.0          # in seconds
    boost_used_sec: float = 0.0
    crit_depth: int = 0               # Nesting depth for hint API
    runnable_at: float = 0.0          # Timestamp when became runnable
    vtime: float = 0.0                # Weighted virtual time
    wait_uaddr: Optional[int] = None  # Futex address blocked on
    nice: int = 0                     # Nice value for vtime weighting

    def effective_class(self, now: float) -> int:
        """Section 10.2: Unified helper for effective class."""
        if self.boost_until > now or self.crit_depth > 0:
            return CLASS_FOREGROUND
        return self.base_class if self.base_class != CLASS_UNSPEC else CLASS_NORMAL


@dataclass
class CpuCtx:
    cpu_id: int
    cur_class: int = CLASS_UNSPEC
    cur_task: Optional[TaskCtx] = None
    run_start: float = 0.0
    last_guard: float = -1e9
    slice_end: float = 0.0


@dataclass
class TraceEvent:
    timestamp: float
    pid: int
    tid: int
    comm: str
    task_class: int
    wait_ms: float
    cpu: int
    event_type: str  # 'dispatch', 'preempt', 'guard', 'boost', 'complete'


class ScxHushScheduler:
    """
    scx_hush scheduler kernel simulator implementing sched_ext ops.
    """

    def __init__(self, nr_cpus: int = 4, config_dict: Optional[Dict[str, Any]] = None):
        self.nr_cpus = nr_cpus
        self.cpus: List[CpuCtx] = [CpuCtx(cpu_id=i) for i in range(nr_cpus)]
        
        # Configuration
        cfg = config_dict or {}
        self.fg_slice_sec = cfg.get("fg_slice_ms", 5) / 1000.0
        self.normal_slice_sec = cfg.get("normal_slice_ms", 10) / 1000.0
        self.bg_slice_sec = cfg.get("bg_slice_ms", 20) / 1000.0
        self.guard_sec = cfg.get("guard_ms", 2000) / 1000.0
        self.boost_sec = cfg.get("boost_ms", 50) / 1000.0
        self.boost_cap_pct = cfg.get("boost_cap_pct", 10)
        self.policy_generation = 1
        self.watchdog_timeout_sec = 8.0

        # DSQs
        # FG_DSQ and NORMAL_DSQ are min-heaps by (vtime, seq, task)
        self._seq = 0
        self.fg_dsq: List[Tuple[float, int, TaskCtx]] = []
        self.normal_dsq: List[Tuple[float, int, TaskCtx]] = []
        # BG_DSQ is a FIFO queue (deque)
        self.bg_dsq: collections.deque[TaskCtx] = collections.deque()
        # Per-CPU local DSQ
        self.local_dsq: Dict[int, collections.deque[TaskCtx]] = {
            i: collections.deque() for i in range(nr_cpus)
        }

        # Rules
        self.rules: List[Dict[str, Any]] = []

        # System state
        self.tasks: Dict[int, TaskCtx] = {}
        self.lock_holders: Dict[int, int] = {} # futex_addr -> holder_tid
        self.lock_waiters: Dict[int, List[int]] = collections.defaultdict(list) # futex_addr -> list of waiter_tids

        # Statistics
        self.stats = {
            "runtime_sec": {c: 0.0 for c in (CLASS_FOREGROUND, CLASS_NORMAL, CLASS_BACKGROUND)},
            "wait_sec": {c: 0.0 for c in (CLASS_FOREGROUND, CLASS_NORMAL, CLASS_BACKGROUND)},
            "preemptions": {c: 0 for c in (CLASS_FOREGROUND, CLASS_NORMAL, CLASS_BACKGROUND)},
            "completed": {c: 0 for c in (CLASS_FOREGROUND, CLASS_NORMAL, CLASS_BACKGROUND)},
            "guard_firings": 0,
            "boost_count": 0,
            "hint_abuse_count": 0,
        }

        # Trace buffer
        self.trace_buffer: List[TraceEvent] = []
        self.trace_enabled = True

    def load_policy(self, toml_path_or_str: str, is_raw_str: bool = False):
        """Loads and parses policy.toml."""
        if is_raw_str:
            data = tomllib.loads(toml_path_or_str)
        else:
            with open(toml_path_or_str, "rb") as f:
                data = tomllib.load(f)

        sched_cfg = data.get("scheduler", {})
        if "guard_ms" in sched_cfg:
            guard_ms = sched_cfg["guard_ms"]
            # FR-12: Must be <= watchdog_timeout / 4
            max_allowed = (self.watchdog_timeout_sec * 1000) / 4
            if guard_ms > max_allowed:
                raise ValueError(
                    f"guard_ms ({guard_ms} ms) exceeds watchdog_timeout/4 ({max_allowed} ms)"
                )
            self.guard_sec = guard_ms / 1000.0

        if "fg_slice_ms" in sched_cfg:
            self.fg_slice_sec = sched_cfg["fg_slice_ms"] / 1000.0
        if "normal_slice_ms" in sched_cfg:
            self.normal_slice_sec = sched_cfg["normal_slice_ms"] / 1000.0
        if "bg_slice_ms" in sched_cfg:
            self.bg_slice_sec = sched_cfg["bg_slice_ms"] / 1000.0
        if "boost_ms" in sched_cfg:
            self.boost_sec = sched_cfg["boost_ms"] / 1000.0
        if "boost_cap_pct" in sched_cfg:
            self.boost_cap_pct = sched_cfg["boost_cap_pct"]

        self.rules = data.get("rule", [])
        self.policy_generation += 1

    def classify_task(self, comm: str, cgroup: str) -> int:
        """FR-2, FR-3: Resolves class using first-match rule order."""
        for rule in self.rules:
            match = rule.get("match", {})
            target_class_str = rule.get("class", "").lower()
            target_class = (
                CLASS_FOREGROUND if target_class_str == "foreground"
                else CLASS_BACKGROUND if target_class_str == "background"
                else CLASS_NORMAL
            )

            # Check cgroup match (supports wildcards)
            if "cgroup" in match:
                pattern = match["cgroup"]
                if fnmatch.fnmatch(cgroup, pattern):
                    return target_class

            # Check comm match
            if "comm" in match:
                comms = match["comm"]
                if isinstance(comms, str):
                    comms = [comms]
                if comm in comms:
                    return target_class

        return CLASS_NORMAL

    def register_task(self, pid: int, tid: int, comm: str, cgroup: str) -> TaskCtx:
        base_class = self.classify_task(comm, cgroup)
        ctx = TaskCtx(
            pid=pid,
            tid=tid,
            comm=comm,
            cgroup=cgroup,
            base_class=base_class,
            policy_gen=self.policy_generation,
        )
        self.tasks[tid] = ctx
        return ctx

    def select_cpu(self, task: TaskCtx, now: float) -> Optional[int]:
        """
        sched_ext select_cpu: If an idle CPU is found, place directly in local DSQ.
        """
        for cpu in self.cpus:
            if cpu.cur_task is None and len(self.local_dsq[cpu.cpu_id]) == 0:
                eff = task.effective_class(now)
                slice_dur = (
                    self.fg_slice_sec if eff == CLASS_FOREGROUND
                    else self.bg_slice_sec if eff == CLASS_BACKGROUND
                    else self.normal_slice_sec
                )
                self.local_dsq[cpu.cpu_id].append(task)
                return cpu.cpu_id
        return None

    def enqueue(self, task: TaskCtx, now: float):
        """
        sched_ext enqueue: places task in class DSQ and triggers preemption kick.
        """
        task.runnable_at = now
        eff = task.effective_class(now)
        self._seq += 1

        if eff == CLASS_FOREGROUND:
            heapq.heappush(self.fg_dsq, (task.vtime, self._seq, task))
            self._kick_background_cpu(now)
        elif eff == CLASS_NORMAL:
            heapq.heappush(self.normal_dsq, (task.vtime, self._seq, task))
            self._kick_background_cpu(now)
        else:
            self.bg_dsq.append(task)

    def _kick_background_cpu(self, now: float):
        """
        Section 7.4: Scans for a CPU running BACKGROUND work and preempts it immediately.
        """
        for cpu in self.cpus:
            if cpu.cur_task and cpu.cur_class == CLASS_BACKGROUND:
                # Preemption kick
                preempted_task = cpu.cur_task
                self._stop_task(cpu, now)
                # Return preempted task to tail of BG_DSQ
                self.bg_dsq.append(preempted_task)
                self.stats["preemptions"][CLASS_BACKGROUND] += 1
                if self.trace_enabled:
                    self.trace_buffer.append(TraceEvent(
                        timestamp=now,
                        pid=preempted_task.pid,
                        tid=preempted_task.tid,
                        comm=preempted_task.comm,
                        task_class=CLASS_BACKGROUND,
                        wait_ms=0.0,
                        cpu=cpu.cpu_id,
                        event_type="preempt"
                    ))
                # Trigger dispatch on this CPU immediately
                self.dispatch(cpu.cpu_id, now)
                break

    def dispatch(self, cpu_id: int, now: float) -> Optional[TaskCtx]:
        """
        sched_ext dispatch: Checks starvation guard, then drains queues in class order.
        """
        cpu = self.cpus[cpu_id]
        if cpu.cur_task is not None:
            return cpu.cur_task

        # If local DSQ has a task, run it
        if self.local_dsq[cpu_id]:
            t = self.local_dsq[cpu_id].popleft()
            self._start_task(cpu, t, now)
            return t

        # Section 7.5: Starvation Guard (FR-11, FR-12)
        # Peek head of BG_DSQ (oldest waiter)
        if self.bg_dsq and (now - cpu.last_guard >= self.guard_sec):
            oldest_bg = self.bg_dsq[0]
            if (now - oldest_bg.runnable_at) >= self.guard_sec:
                # Grant one guard slice
                t = self.bg_dsq.popleft()
                cpu.last_guard = now
                self.stats["guard_firings"] += 1
                if self.trace_enabled:
                    self.trace_buffer.append(TraceEvent(
                        timestamp=now,
                        pid=t.pid,
                        tid=t.tid,
                        comm=t.comm,
                        task_class=CLASS_BACKGROUND,
                        wait_ms=(now - t.runnable_at) * 1000.0,
                        cpu=cpu_id,
                        event_type="guard"
                    ))
                self._start_task(cpu, t, now)
                return t

        # Strict priority class order:
        # 1. FG_DSQ
        if self.fg_dsq:
            _, _, t = heapq.heappop(self.fg_dsq)
            self._start_task(cpu, t, now)
            return t

        # 2. NORMAL_DSQ
        if self.normal_dsq:
            _, _, t = heapq.heappop(self.normal_dsq)
            self._start_task(cpu, t, now)
            return t

        # 3. BG_DSQ (only when no FG or NORMAL task is runnable - FR-6)
        if self.bg_dsq:
            t = self.bg_dsq.popleft()
            self._start_task(cpu, t, now)
            return t

        return None

    def _start_task(self, cpu: CpuCtx, task: TaskCtx, now: float):
        eff = task.effective_class(now)
        cpu.cur_task = task
        cpu.cur_class = eff
        cpu.run_start = now
        
        slice_dur = (
            self.fg_slice_sec if eff == CLASS_FOREGROUND
            else self.bg_slice_sec if eff == CLASS_BACKGROUND
            else self.normal_slice_sec
        )
        cpu.slice_end = now + slice_dur

        wait_time = max(0.0, now - task.runnable_at)
        self.stats["wait_sec"][eff] += wait_time

        if self.trace_enabled:
            self.trace_buffer.append(TraceEvent(
                timestamp=now,
                pid=task.pid,
                tid=task.tid,
                comm=task.comm,
                task_class=eff,
                wait_ms=wait_time * 1000.0,
                cpu=cpu.cpu_id,
                event_type="dispatch"
            ))

    def _stop_task(self, cpu: CpuCtx, now: float):
        task = cpu.cur_task
        if not task:
            return
        run_delta = max(0.0, now - cpu.run_start)
        eff = cpu.cur_class
        if eff in self.stats["runtime_sec"]:
            self.stats["runtime_sec"][eff] += run_delta
        
        # Charge vtime
        task.vtime += run_delta
        if task.boost_until > now:
            task.boost_used_sec += run_delta

        cpu.cur_task = None
        cpu.cur_class = CLASS_UNSPEC
        cpu.run_start = 0.0
        cpu.slice_end = 0.0

    def tick(self, now: float):
        """
        Timer tick callback:
        Backstop: If BG task is running and FG tasks are waiting, preempt.
        Also handles slice expiration.
        """
        for cpu in self.cpus:
            if cpu.cur_task:
                # Backstop check
                if cpu.cur_class == CLASS_BACKGROUND:
                    if len(self.fg_dsq) > 0 or len(self.normal_dsq) > 0:
                        task = cpu.cur_task
                        self._stop_task(cpu, now)
                        self.bg_dsq.append(task)
                        self.dispatch(cpu.cpu_id, now)
                        continue

                # Slice expiration
                if now >= cpu.slice_end:
                    task = cpu.cur_task
                    self._stop_task(cpu, now)
                    self.enqueue(task, now)
                    self.dispatch(cpu.cpu_id, now)

    # --- Priority Inversion Handling (Section 8) ---

    def hint_critical_enter(self, tid: int, now: float):
        """Tier 1: Uprobe on hush_critical_enter."""
        task = self.tasks.get(tid)
        if not task:
            return
        # Abuse check (10% cap)
        if task.boost_used_sec > 0.10: # >100ms per sec
            self.stats["hint_abuse_count"] += 1
            return
        task.crit_depth += 1
        self.stats["boost_count"] += 1

    def hint_critical_exit(self, tid: int):
        """Tier 1: Uprobe on hush_critical_exit."""
        task = self.tasks.get(tid)
        if task and task.crit_depth > 0:
            task.crit_depth -= 1

    def futex_wait(self, waiter_tid: int, uaddr: int, now: float):
        """Tier 2 & 3: Futex contention handling."""
        waiter = self.tasks.get(waiter_tid)
        if not waiter:
            return
        waiter.wait_uaddr = uaddr
        self.lock_waiters[uaddr].append(waiter_tid)

        # Check if holder is BACKGROUND and waiter is FOREGROUND
        holder_tid = self.lock_holders.get(uaddr)
        if holder_tid and waiter.effective_class(now) == CLASS_FOREGROUND:
            holder = self.tasks.get(holder_tid)
            if holder and holder.effective_class(now) == CLASS_BACKGROUND:
                # Boost holder!
                holder.boost_until = now + self.boost_sec
                self.stats["boost_count"] += 1
                if self.trace_enabled:
                    self.trace_buffer.append(TraceEvent(
                        timestamp=now,
                        pid=holder.pid,
                        tid=holder.tid,
                        comm=holder.comm,
                        task_class=CLASS_FOREGROUND,
                        wait_ms=0.0,
                        cpu=-1,
                        event_type="boost"
                    ))
                # If holder is in BG_DSQ, promote to local DSQ or FG
                if holder in self.bg_dsq:
                    self.bg_dsq.remove(holder)
                    self.enqueue(holder, now)

    def futex_wake(self, holder_tid: int, uaddr: int, now: float):
        """Futex release / wake."""
        self.lock_holders.pop(uaddr, None)
        waiters = self.lock_waiters.pop(uaddr, [])
        for w_tid in waiters:
            w_task = self.tasks.get(w_tid)
            if w_task:
                w_task.wait_uaddr = None
                self.enqueue(w_task, now)

    def acquire_lock(self, holder_tid: int, uaddr: int):
        self.lock_holders[uaddr] = holder_tid

