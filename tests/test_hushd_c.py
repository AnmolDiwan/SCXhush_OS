"""
Integration tests for the C daemon's control plane (hushd/), run with
--no-load so no sched_ext kernel or root is needed. The BPF side is covered by
the build (make bpf) and by on-hardware runs; see docs/IMPLEMENTATION_PLAN.md §4.
"""

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from cli.hushctl import send_command

ROOT = Path(__file__).resolve().parent.parent
HUSHD = ROOT / "build" / "hushd"
GOOD = ROOT / "tests" / "c" / "fixtures" / "good.toml"

pytestmark = pytest.mark.skipif(not HUSHD.exists(), reason="build/hushd not built (run make)")


@pytest.fixture()
def cgroot(tmp_path):
    for d in ("user.slice/user-1000.slice/session-3.scope/app",
              "system.slice/backup.service", "system.slice/sshd.service"):
        (tmp_path / "cg" / d).mkdir(parents=True)
    return tmp_path / "cg"


@pytest.fixture()
def hushd(tmp_path, cgroot):
    sock = tmp_path / "hush.sock"
    policy = tmp_path / "policy.toml"
    shutil.copy(GOOD, policy)
    proc = subprocess.Popen(
        [str(HUSHD), "--no-load", "-p", str(policy), "-s", str(sock), "--cgroup-root", str(cgroot)],
        stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.02)
    else:
        proc.kill()
        pytest.fail("hushd did not create its socket: " + proc.stderr.read())
    yield {"sock": str(sock), "policy": policy, "proc": proc, "cg": cgroot}
    proc.terminate()
    proc.wait(5)


def test_dry_run_resolves_cgroups(cgroot):
    out = subprocess.run([str(HUSHD), "--dry-run", "-p", str(GOOD), "--cgroup-root", str(cgroot)],
                         capture_output=True, text=True, check=True).stdout
    assert "/user.slice/user-1000.slice/session-3.scope/app" in out
    assert "comm   cc1              -> BACKGROUND" in out
    # First match wins: rustc is listed by an earlier background rule.
    assert "rustc            -> FOREGROUND" not in out


def test_rejects_unsafe_guard(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("[scheduler]\nguard_ms = 9000\n")
    r = subprocess.run([str(HUSHD), "--dry-run", "-p", str(bad)], capture_output=True, text=True)
    assert r.returncode == 2
    assert "watchdog_ms/4" in r.stderr


def test_status_and_overrides(hushd):
    s = hushd["sock"]
    st = send_command("status", sock_path=s)
    assert st["backend"] == "no-load"
    assert st["cgroups_classified"] == 5  # user.slice x2, session scope x2, backup.service
    gen = st["policy_gen"]

    me = os.getpid()
    assert send_command("promote", {"target": str(me)}, sock_path=s)["status"] == "ok"
    c = send_command("class", {"pid": me}, sock_path=s)
    assert c["policy_class"] == "FOREGROUND" and c["policy_match"] == "pid override"
    assert send_command("reset", {"target": str(me)}, sock_path=s)["status"] == "ok"

    r = send_command("demote", {"target": "/system.slice/sshd.service"}, sock_path=s)
    assert r["status"] == "ok"
    assert send_command("status", sock_path=s)["policy_gen"] == gen + 3
    assert send_command("promote", {"target": "/missing"}, sock_path=s)["status"] == "error"


def test_reload_keeps_old_policy_on_error(hushd):
    s = hushd["sock"]
    hushd["policy"].write_text("[scheduler]\nguard_ms = 9000\n")
    r = send_command("reload", sock_path=s)
    assert r["status"] == "error" and "keeping the current policy" in r["message"]
    assert send_command("status", sock_path=s)["config"]["guard_ms"] == 2000

    hushd["policy"].write_text("[scheduler]\nguard_ms = 1000\n")
    r = send_command("reload", sock_path=s)
    assert r["status"] == "ok"
    assert send_command("status", sock_path=s)["config"]["guard_ms"] == 1000


def test_new_cgroup_is_classified(hushd):
    before = send_command("status", sock_path=hushd["sock"])["cgroups_classified"]
    (hushd["cg"] / "system.slice" / "backup.service" / "late").mkdir()
    for _ in range(50):
        if send_command("status", sock_path=hushd["sock"])["cgroups_classified"] == before + 1:
            return
        time.sleep(0.02)
    pytest.fail("inotify did not pick up the new cgroup")


def test_sighup_reload(hushd):
    gen = send_command("status", sock_path=hushd["sock"])["policy_gen"]
    hushd["proc"].send_signal(1)  # SIGHUP
    for _ in range(50):
        if send_command("status", sock_path=hushd["sock"])["policy_gen"] > gen:
            return
        time.sleep(0.02)
    pytest.fail("SIGHUP did not reload the policy")


def test_malformed_request(hushd):
    import socket
    with socket.socket(socket.AF_UNIX) as c:
        c.connect(hushd["sock"])
        c.sendall(b'{"cmd": "status"\n')
        assert b'"status":"error"' in c.recv(4096)
