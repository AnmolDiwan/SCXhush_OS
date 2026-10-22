"""
Unit tests for scx_hush Starvation Guard (FR-11, FR-12).
"""

from sim.scheduler_core import (
    ScxHushScheduler,
    CLASS_FOREGROUND,
    CLASS_BACKGROUND,
)


def test_starvation_guard_grants_slice_after_interval():
    """FR-11: BG task waiting longer than guard_interval is granted one slice."""
    sched = ScxHushScheduler(nr_cpus=1)
    sched.guard_sec = 2.0 # 2 seconds
    t0 = 1000.0

    # Continuous FG tasks enqueued
    fg1 = sched.register_task(pid=1, tid=1, comm="fg1", cgroup="/user.slice")
    fg1.base_class = CLASS_FOREGROUND
    sched.enqueue(fg1, t0)

    # BG task enqueued at t0
    bg = sched.register_task(pid=2, tid=2, comm="bg", cgroup="/system.slice")
    bg.base_class = CLASS_BACKGROUND
    sched.enqueue(bg, t0)

    # At t0 + 1.5s (< guard interval), FG task still runs
    dispatched = sched.dispatch(cpu_id=0, now=t0 + 1.5)
    assert dispatched.tid == fg1.tid

    # Finish FG task, enqueue new FG task
    sched._stop_task(sched.cpus[0], t0 + 2.1)
    fg2 = sched.register_task(pid=3, tid=3, comm="fg2", cgroup="/user.slice")
    fg2.base_class = CLASS_FOREGROUND
    sched.enqueue(fg2, t0 + 2.1)

    # At t0 + 2.1s (> guard interval of 2.0s), guard MUST fire and grant BG task a slice
    dispatched = sched.dispatch(cpu_id=0, now=t0 + 2.1)
    assert dispatched.tid == bg.tid
    assert sched.stats["guard_firings"] == 1


def test_starvation_guard_per_cpu_rate_limiting():
    """FR-12: Guard slice is rate-limited per CPU (at most 1 per guard_interval)."""
    sched = ScxHushScheduler(nr_cpus=1)
    sched.guard_sec = 2.0
    t0 = 1000.0

    # Register two starving BG tasks
    bg1 = sched.register_task(pid=1, tid=1, comm="bg1", cgroup="/system.slice")
    bg1.base_class = CLASS_BACKGROUND
    sched.enqueue(bg1, t0)

    bg2 = sched.register_task(pid=2, tid=2, comm="bg2", cgroup="/system.slice")
    bg2.base_class = CLASS_BACKGROUND
    sched.enqueue(bg2, t0)

    # At t0 + 2.1s, guard grants slice to bg1
    d1 = sched.dispatch(cpu_id=0, now=t0 + 2.1)
    assert d1.tid == bg1.tid

    # Stop bg1 at t0 + 2.12s
    sched._stop_task(sched.cpus[0], t0 + 2.12)

    # Add FG task
    fg = sched.register_task(pid=3, tid=3, comm="fg", cgroup="/user.slice")
    fg.base_class = CLASS_FOREGROUND
    sched.enqueue(fg, t0 + 2.12)

    # Dispatch at t0 + 2.13s: rate limit must prevent second guard slice within 2.0s!
    d2 = sched.dispatch(cpu_id=0, now=t0 + 2.13)
    assert d2.tid == fg.tid
