"""
Unit tests for scx_hush core scheduling logic:
DSQ order, work conservation, preemption kick, tick backstop.
"""

import pytest
from sim.scheduler_core import (
    ScxHushScheduler,
    CLASS_FOREGROUND,
    CLASS_NORMAL,
    CLASS_BACKGROUND,
)


def test_strict_foreground_isolation():
    """FR-6: Background task runs only when no FG or NORMAL task is runnable."""
    sched = ScxHushScheduler(nr_cpus=1)
    t_now = 100.0

    # Register BG task and FG task
    bg_task = sched.register_task(pid=10, tid=10, comm="rustc", cgroup="/system.slice")
    bg_task.base_class = CLASS_BACKGROUND

    fg_task = sched.register_task(pid=20, tid=20, comm="game", cgroup="/user.slice")
    fg_task.base_class = CLASS_FOREGROUND

    # Enqueue both
    sched.enqueue(bg_task, t_now)
    sched.enqueue(fg_task, t_now)

    # Dispatch on CPU 0
    dispatched = sched.dispatch(cpu_id=0, now=t_now)
    # Must dispatch FG task first!
    assert dispatched is not None
    assert dispatched.tid == fg_task.tid
    assert sched.cpus[0].cur_class == CLASS_FOREGROUND


def test_immediate_preemption_of_background_core():
    """FR-7: When FG task wakes and core is running BG, kick preempts BG immediately."""
    sched = ScxHushScheduler(nr_cpus=1)
    t_now = 100.0

    # Start CPU 0 with BG task
    bg_task = sched.register_task(pid=10, tid=10, comm="zstd", cgroup="/system.slice")
    bg_task.base_class = CLASS_BACKGROUND
    sched.enqueue(bg_task, t_now)
    sched.dispatch(cpu_id=0, now=t_now)
    assert sched.cpus[0].cur_task.tid == bg_task.tid

    # Now a FG task wakes up
    t_wake = 100.002 # 2ms later
    fg_task = sched.register_task(pid=20, tid=20, comm="compositor", cgroup="/user.slice")
    fg_task.base_class = CLASS_FOREGROUND

    # Enqueue triggers preemption kick
    sched.enqueue(fg_task, t_wake)

    # Preemption check: CPU 0 must now be running the FG task
    assert sched.cpus[0].cur_task.tid == fg_task.tid
    assert sched.stats["preemptions"][CLASS_BACKGROUND] == 1


def test_virtual_time_sharing_among_foreground():
    """FR-8: FG tasks are ordered by weighted virtual time (vtime)."""
    sched = ScxHushScheduler(nr_cpus=1)
    t_now = 100.0

    t1 = sched.register_task(pid=1, tid=1, comm="fg1", cgroup="/user.slice")
    t1.base_class = CLASS_FOREGROUND
    t1.vtime = 50.0

    t2 = sched.register_task(pid=2, tid=2, comm="fg2", cgroup="/user.slice")
    t2.base_class = CLASS_FOREGROUND
    t2.vtime = 10.0 # lower vtime, should run first

    sched.enqueue(t1, t_now)
    sched.enqueue(t2, t_now)

    dispatched = sched.dispatch(cpu_id=0, now=t_now)
    assert dispatched.tid == t2.tid

