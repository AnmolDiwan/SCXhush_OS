"""
Unit tests for scx_hush policy classification (FR-1, FR-2, FR-3, FR-4).
"""

import pytest
from sim.scheduler_core import (
    ScxHushScheduler,
    CLASS_FOREGROUND,
    CLASS_NORMAL,
    CLASS_BACKGROUND,
)

SAMPLE_POLICY = """
[scheduler]
fg_slice_ms = 5
normal_slice_ms = 10
bg_slice_ms = 20
guard_ms = 2000
boost_ms = 50
boost_cap_pct = 10

[[rule]]
match = { cgroup = "/user.slice/user-1000.slice/session-*.scope" }
class = "foreground"

[[rule]]
match = { comm = ["cc1", "cc1plus", "rustc", "ld", "restic"] }
class = "background"

[[rule]]
match = { cgroup = "/system.slice/backup.service" }
class = "background"

[[rule]]
match = { comm = ["schbench", "browser"] }
class = "foreground"
"""


def test_policy_classification_cgroup_precedence():
    sched = ScxHushScheduler()
    sched.load_policy(SAMPLE_POLICY, is_raw_str=True)

    # FR-1, FR-2: Cgroup match
    cls = sched.classify_task("bash", "/user.slice/user-1000.slice/session-1.scope")
    assert cls == CLASS_FOREGROUND

    # FR-3: Comm match
    cls_bg = sched.classify_task("rustc", "/user.slice/other.scope")
    assert cls_bg == CLASS_BACKGROUND

    # Fallback to NORMAL
    cls_norm = sched.classify_task("random_daemon", "/system.slice/other.service")
    assert cls_norm == CLASS_NORMAL


def test_guard_validation_watchdog_limit():
    sched = ScxHushScheduler()
    sched.watchdog_timeout_sec = 8.0 # Max allowed guard = 2000 ms

    bad_policy = """
    [scheduler]
    guard_ms = 3000
    """
    # FR-12: Must refuse guard_ms > watchdog_timeout / 4
    with pytest.raises(ValueError, match="exceeds watchdog_timeout/4"):
        sched.load_policy(bad_policy, is_raw_str=True)


def test_policy_reload_generation_bump():
    sched = ScxHushScheduler()
    sched.load_policy(SAMPLE_POLICY, is_raw_str=True)
    gen1 = sched.policy_generation

    # Reload bumps generation
    sched.load_policy(SAMPLE_POLICY, is_raw_str=True)
    assert sched.policy_generation == gen1 + 1

