"""
hushctl against the simulator daemon (daemon/hushd.py) over a Unix socket.
Covers the shared control protocol: status, class, promote/demote/reset,
reload, selftest and trace.
"""

import threading

import pytest

from cli.hushctl import HushctlError, main as hushctl_main, send_command
from daemon.hushd import HushDaemon


@pytest.fixture(scope="module")
def sock(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("hush") / "sim.sock")
    daemon = HushDaemon(sock_path=path)
    t = threading.Thread(target=daemon.start, daemon=True)
    t.start()
    assert daemon.ready.wait(5)
    yield path
    daemon.stop()
    t.join(2)


def test_status_schema(sock):
    r = send_command("status", sock_path=sock)
    assert r["status"] == "ok"
    assert r["backend"] == "sim"
    assert set(r["classes"]) == {"FOREGROUND", "NORMAL", "BACKGROUND"}
    assert "runtime_ns" in r["classes"]["FOREGROUND"]
    assert r["config"]["guard_ms"] == 2000


def test_selftest_is_honest_about_backend(sock):
    r = send_command("selftest", sock_path=sock)
    assert r["status"] == "ok"
    assert r["verdict"] == "simulator only"
    assert not r["checks"][0]["ok"]


def test_promote_demote_reset(sock):
    assert send_command("promote", {"target": "999"}, sock_path=sock)["status"] == "ok"
    r = send_command("class", {"pid": 999}, sock_path=sock)
    assert r["effective_class"] == "FOREGROUND"
    assert r["policy_match"] == "pid override"

    assert send_command("demote", {"target": "999"}, sock_path=sock)["status"] == "ok"
    assert send_command("class", {"pid": 999}, sock_path=sock)["effective_class"] == "BACKGROUND"

    assert send_command("reset", {"target": "999"}, sock_path=sock)["status"] == "ok"
    assert send_command("class", {"pid": 999}, sock_path=sock)["policy_match"] == "rules"


def test_cgroup_target_must_be_absolute(sock):
    r = send_command("promote", {"target": "user.slice"}, sock_path=sock)
    assert r["status"] == "error"


def test_reload_bumps_generation(sock):
    before = send_command("status", sock_path=sock)["policy_gen"]
    r = send_command("reload", sock_path=sock)
    assert r["status"] == "ok"
    assert r["policy_gen"] > before


def test_unknown_command(sock):
    r = send_command("frobnicate", sock_path=sock)
    assert r["status"] == "error"


def test_trace_roundtrip(sock, tmp_path):
    out = tmp_path / "trace.csv"
    assert send_command("trace", {"action": "start", "file": str(out)}, sock_path=sock)["status"] == "ok"
    assert send_command("trace", {"action": "stop"}, sock_path=sock)["status"] == "ok"
    assert out.read_text().startswith("timestamp_ns,pid,tid,comm,class,wait_ns,cpu")


def test_cli_rendering(sock, capsys):
    assert hushctl_main(["--socket", sock, "status"]) == 0
    out = capsys.readouterr().out
    assert "FOREGROUND" in out and "guard firings" in out


def test_cli_reports_missing_daemon(tmp_path, capsys):
    assert hushctl_main(["--socket", str(tmp_path / "none.sock"), "status"]) == 1
    assert "cannot reach hushd" in capsys.readouterr().err
    with pytest.raises(HushctlError):
        send_command("status", sock_path=str(tmp_path / "none.sock"))
