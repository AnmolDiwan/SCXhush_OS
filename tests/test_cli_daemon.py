"""
Integration test for hushd daemon and hushctl CLI.
Tests live IPC socket commands: status, class, promote, demote, reload, selftest, trace.
"""

import time
import socket
import threading
import pytest
from daemon.hushd import HushDaemon, TCP_FALLBACK_PORT
from cli.hushctl import send_command


@pytest.fixture(scope="module")
def running_daemon():
    test_port = TCP_FALLBACK_PORT + 10
    daemon = HushDaemon(port=test_port)
    server_thread = threading.Thread(target=daemon.start)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(0.5) # Wait for server startup
    yield test_port
    daemon.stop()
    time.sleep(0.2)


def test_cli_status(running_daemon):
    port = running_daemon
    res = send_command("status", {}, port=port)
    assert res.get("status") == "ok"
    assert "policy_gen" in res
    assert "runtime_sec" in res


def test_cli_selftest(running_daemon):
    port = running_daemon
    res = send_command("selftest", {}, port=port)
    assert res.get("status") == "ok"
    assert res.get("verdict") == "All compatibility checks passed"


def test_cli_promote_and_class(running_daemon):
    port = running_daemon
    # Promote PID 999
    prom_res = send_command("promote", {"target": "999"}, port=port)
    assert prom_res.get("status") == "ok"

    # Query class of PID 999
    cls_res = send_command("class", {"pid": 999}, port=port)
    assert cls_res.get("status") == "ok"
    assert cls_res.get("effective_class") == "FOREGROUND"


def test_cli_demote(running_daemon):
    port = running_daemon
    dem_res = send_command("demote", {"target": "999"}, port=port)
    assert dem_res.get("status") == "ok"

    cls_res = send_command("class", {"pid": 999}, port=port)
    assert cls_res.get("status") == "ok"
    assert cls_res.get("effective_class") == "BACKGROUND"


def test_cli_reload(running_daemon):
    port = running_daemon
    res = send_command("reload", {}, port=port)
    assert res.get("status") == "ok"

