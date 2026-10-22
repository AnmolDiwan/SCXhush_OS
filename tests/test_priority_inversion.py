"""
Unit tests for Priority Inversion Handling (FR-13, FR-14, FR-15, NFR-3).
"""

from sim.scheduler_core import (
    ScxHushScheduler,
    CLASS_FOREGROUND,
    CLASS_BACKGROUND,
)


def test_hint_api_critical_enter_exit():
    """FR-13: Hint API marks task as critical, boosting it to FOREGROUND."""
    sched = ScxHushScheduler(nr_cpus=1)
    t_now = 50.0

    task = sched.register_task(pid=10, tid=10, comm="vacuum", cgroup="/system.slice")
    task.base_class = CLASS_BACKGROUND
    assert task.effective_class(t_now) == CLASS_BACKGROUND

    # Call hush_critical_enter
    sched.hint_critical_enter(tid=10, now=t_now)
    assert task.effective_class(t_now) == CLASS_FOREGROUND
    assert task.crit_depth == 1

    # Call hush_critical_exit
    sched.hint_critical_exit(tid=10)
    assert task.effective_class(t_now) == CLASS_BACKGROUND
    assert task.crit_depth == 0


def test_hint_abuse_cap():
    """NFR-3 / Section 8.3: Hint abuse cap at 10% runtime per sec."""
    sched = ScxHushScheduler(nr_cpus=1)
    t_now = 50.0

    task = sched.register_task(pid=10, tid=10, comm="abusive_app", cgroup="/system.slice")
    task.base_class = CLASS_BACKGROUND
    task.boost_used_sec = 0.15 # 150 ms in current second (> 10%)

    sched.hint_critical_enter(tid=10, now=t_now)
    # Hint must be ignored and abuse counter incremented
    assert task.crit_depth == 0
    assert sched.stats["hint_abuse_count"] == 1


def test_futex_priority_inversion_boost():
    """FR-14: FG blocked on futex held by BG boosts holder to FOREGROUND."""
    sched = ScxHushScheduler(nr_cpus=1)
    t_now = 100.0
    futex_addr = 0x7fff12340000

    # BG thread B holds lock
    bg_holder = sched.register_task(pid=10, tid=10, comm="db_vacuum", cgroup="/system.slice")
    bg_holder.base_class = CLASS_BACKGROUND
    sched.acquire_lock(holder_tid=10, uaddr=futex_addr)
    sched.enqueue(bg_holder, t_now)

    # FG thread A tries to acquire lock and blocks on futex
    fg_waiter = sched.register_task(pid=20, tid=20, comm="db_query", cgroup="/user.slice")
    fg_waiter.base_class = CLASS_FOREGROUND

    # FUTEX_WAIT
    sched.futex_wait(waiter_tid=20, uaddr=futex_addr, now=t_now)

    # BG holder must now be boosted to FOREGROUND
    assert bg_holder.effective_class(t_now) == CLASS_FOREGROUND
    assert bg_holder.boost_until == t_now + sched.boost_sec

    # Dispatch: boosted holder runs as FOREGROUND
    dispatched = sched.dispatch(cpu_id=0, now=t_now)
    assert dispatched.tid == bg_holder.tid


def test_boost_expiry():
    """FR-15: Boost expires automatically after bounded time."""
    sched = ScxHushScheduler(nr_cpus=1)
    t0 = 100.0
    task = sched.register_task(pid=10, tid=10, comm="task", cgroup="/system.slice")
    task.base_class = CLASS_BACKGROUND
    task.boost_until = t0 + 0.050 # 50 ms boost

    assert task.effective_class(t0 + 0.020) == CLASS_FOREGROUND
    # After 50 ms
    assert task.effective_class(t0 + 0.051) == CLASS_BACKGROUND
