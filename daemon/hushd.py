#!/usr/bin/env python3
"""
hushd-sim - the hushd control protocol in front of the Python simulator.

This is not the scheduler. The real daemon is the C program in hushd/ that
loads scx_hush into a sched_ext kernel. This one drives sim/scheduler_core.py
so that hushctl, the web demo and the tests work on any OS. It speaks the same
newline-delimited JSON as hushd, and replies use the same schema, with
"backend": "sim".

    python daemon/hushd.py --socket /tmp/hush-sim.sock
    python daemon/hushd.py --tcp 19890        # platforms without AF_UNIX
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from sim.scheduler_core import (  # noqa: E402
    CLASS_BACKGROUND,
    CLASS_FOREGROUND,
    CLASS_NAMES,
    CLASS_NORMAL,
    ScxHushScheduler,
)

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "policy.toml"
TCP_FALLBACK_PORT = 19890
VERSION = "0.2.0-sim"


class HushDaemon:
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH,
                 sock_path: Optional[str] = None, port: Optional[int] = None):
        if sock_path is None and port is None:
            port = TCP_FALLBACK_PORT
        self.config_path = Path(config_path)
        self.sock_path = sock_path
        self.port = port
        self.running = False
        self.ready = threading.Event()
        self.scheduler = ScxHushScheduler(nr_cpus=4)
        self.server_sock: Optional[socket.socket] = None
        self.trace_file: Optional[str] = None
        self.start_time = time.monotonic()
        self.pid_overrides: Dict[int, int] = {}
        self._load_policy()

    # ------------------------------------------------------------ lifecycle

    def _load_policy(self):
        self.scheduler.load_policy(str(self.config_path))

    def _bind(self) -> socket.socket:
        if self.sock_path:
            try:
                os.unlink(self.sock_path)
            except FileNotFoundError:
                pass
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(self.sock_path)
            where = self.sock_path
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", self.port))
            where = f"127.0.0.1:{self.port}"
        s.listen(16)
        s.settimeout(0.2)
        print(f"[hushd-sim] simulator backend listening on {where}", file=sys.stderr)
        return s

    def start(self):
        self.server_sock = self._bind()
        self.running = True
        self.ready.set()
        try:
            while self.running:
                try:
                    conn, _ = self.server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
        finally:
            self.stop()

    def stop(self):
        if not self.running:
            return
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
        if self.sock_path:
            try:
                os.unlink(self.sock_path)
            except OSError:
                pass

    def _handle_client(self, conn: socket.socket):
        buf = b""
        with conn:
            conn.settimeout(5.0)
            while True:
                try:
                    chunk = conn.recv(8192)
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    lines = [buf] if buf.strip() else []
                    buf = b""
                else:
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        req = json.loads(line.decode())
                        resp = self.dispatch(req.get("cmd"), req.get("args") or {})
                    except Exception as e:  # malformed request
                        resp = {"status": "error", "message": str(e)}
                    conn.sendall((json.dumps(resp) + "\n").encode())
                if not chunk:
                    return

    # ------------------------------------------------------------ commands

    def dispatch(self, cmd: str, args: Dict[str, Any]) -> Dict[str, Any]:
        handler = getattr(self, f"cmd_{cmd}", None) if cmd else None
        if handler is None:
            return {"status": "error", "message": f"unknown command '{cmd}'"}
        return handler(args)

    def cmd_ping(self, args):
        return {"status": "ok", "message": "pong"}

    def cmd_status(self, args):
        st = self.scheduler.stats
        classes = {}
        for c in (CLASS_FOREGROUND, CLASS_NORMAL, CLASS_BACKGROUND):
            classes[CLASS_NAMES[c]] = {
                "runtime_ns": int(st["runtime_sec"][c] * 1e9),
                "wait_ns": int(st["wait_sec"][c] * 1e9),
                "wait_max_ns": 0,
                "runs": st["completed"][c],
            }
        s = self.scheduler
        return {
            "status": "ok",
            "backend": "sim",
            "version": VERSION,
            "policy": str(self.config_path),
            "policy_gen": s.policy_generation,
            "sched_ext_state": "simulated",
            "ops": "",
            "uptime_s": int(time.monotonic() - self.start_time),
            "cgroups_classified": 0,
            "pid_overrides": len(self.pid_overrides),
            "cgroup_overrides": 0,
            "classes": classes,
            "counters": {
                "preempt_kicks": st["preemptions"][CLASS_BACKGROUND],
                "guard_firings": st["guard_firings"],
                "boosts_hint": st["boost_count"],
                "hint_abuse": st["hint_abuse_count"],
            },
            "features": {"inversion": True, "hints": True, "trace": s.trace_enabled},
            "config": {
                "fg_slice_ms": round(s.fg_slice_sec * 1000),
                "normal_slice_ms": round(s.normal_slice_sec * 1000),
                "bg_slice_ms": round(s.bg_slice_sec * 1000),
                "guard_ms": round(s.guard_sec * 1000),
                "boost_ms": round(s.boost_sec * 1000),
                "boost_cap_pct": s.boost_cap_pct,
                "watchdog_ms": round(s.watchdog_timeout_sec * 1000),
            },
        }

    def cmd_class(self, args):
        try:
            pid = int(args.get("pid", 0))
        except (TypeError, ValueError):
            return {"status": "error", "message": "class: need a numeric pid"}
        task = self.scheduler.tasks.get(pid)
        if not task:
            return {"status": "error", "message": f"pid {pid}: not a simulated task"}
        eff = task.effective_class(time.time())
        return {
            "status": "ok",
            "pid": pid,
            "tgid": task.pid,
            "comm": task.comm,
            "cgroup": task.cgroup,
            "policy_class": CLASS_NAMES[task.base_class],
            "policy_match": "pid override" if pid in self.pid_overrides else "rules",
            "base_class": CLASS_NAMES[task.base_class],
            "effective_class": CLASS_NAMES[eff],
            "reason": "boosted" if eff != task.base_class else "policy",
            "crit_depth": task.crit_depth,
        }

    def _set_pid_class(self, target, cls, verb):
        pid = int(target)
        task = self.scheduler.tasks.get(pid) or self.scheduler.register_task(
            pid, pid, f"task_{pid}", "/sim.slice")
        if cls is None:
            self.pid_overrides.pop(pid, None)
            task.base_class = self.scheduler.classify_task(task.comm, task.cgroup)
        else:
            self.pid_overrides[pid] = cls
            task.base_class = cls
        self.scheduler.policy_generation += 1
        return {"status": "ok", "message": f"process {pid} {verb}"}

    def _set_cgroup_class(self, target, cls, verb):
        if not str(target).startswith("/"):
            return {"status": "error", "message": "cgroup path must start with '/'"}
        self.scheduler.rules = [r for r in self.scheduler.rules
                                if r.get("match", {}).get("cgroup") != f"{target}*"]
        if cls is not None:
            self.scheduler.rules.insert(0, {"match": {"cgroup": f"{target}*"},
                                            "class": CLASS_NAMES[cls].lower()})
        self.scheduler.policy_generation += 1
        return {"status": "ok", "message": f"cgroup {target} {verb}"}

    def _set_class(self, args, cls, verb):
        target = str(args.get("target", ""))
        if not target:
            return {"status": "error", "message": "need a target: <pid> or <cgroup path>"}
        if target.isdigit():
            return self._set_pid_class(target, cls, verb)
        return self._set_cgroup_class(target, cls, verb)

    def cmd_promote(self, args):
        return self._set_class(args, CLASS_FOREGROUND, "promoted to FOREGROUND")

    def cmd_demote(self, args):
        return self._set_class(args, CLASS_BACKGROUND, "demoted to BACKGROUND")

    def cmd_reset(self, args):
        return self._set_class(args, None, "reset to policy")

    def cmd_reload(self, args):
        try:
            self._load_policy()
        except Exception as e:
            return {"status": "error",
                    "message": f"reload rejected, keeping the current policy: {e}"}
        gen = self.scheduler.policy_generation
        return {"status": "ok", "message": f"policy reloaded (generation {gen})", "policy_gen": gen}

    def cmd_selftest(self, args):
        return {
            "status": "ok",
            "checks": [{
                "name": "backend", "ok": False, "fatal": False,
                "detail": "simulator backend: no kernel checks run; use the C hushd on Linux",
            }],
            "tier3_enabled": False,
            "verdict": "simulator only",
        }

    def cmd_trace(self, args):
        action = args.get("action")
        path = args.get("file") or "hush-trace.csv"
        if action == "start":
            self.scheduler.trace_buffer.clear()
            self.scheduler.trace_enabled = True
            self.trace_file = path
            return {"status": "ok", "message": f"tracing wakeup latency to {path}"}
        if action == "stop":
            self.scheduler.trace_enabled = False
            out = self.trace_file or path
            with open(out, "w") as f:
                f.write("timestamp_ns,pid,tid,comm,class,wait_ns,cpu\n")
                for ev in self.scheduler.trace_buffer:
                    f.write(f"{int(ev.timestamp * 1e9)},{ev.pid},{ev.tid},{ev.comm},"
                            f"{CLASS_NAMES[ev.task_class]},{int(ev.wait_ms * 1e6)},{ev.cpu}\n")
            n = len(self.scheduler.trace_buffer)
            return {"status": "ok", "message": f"wrote {n} events to {out}"}
        return {"status": "error", "message": "trace: action must be start or stop"}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--policy", default=str(DEFAULT_CONFIG_PATH))
    g = p.add_mutually_exclusive_group()
    g.add_argument("--socket", help="Unix socket path")
    g.add_argument("--tcp", type=int, help="TCP port on 127.0.0.1")
    a = p.parse_args(argv)
    if a.socket is None and a.tcp is None:
        if hasattr(socket, "AF_UNIX"):
            a.socket = "/tmp/hush-sim.sock"
        else:
            a.tcp = TCP_FALLBACK_PORT

    daemon = HushDaemon(Path(a.policy), sock_path=a.socket, port=a.tcp)
    signal.signal(signal.SIGINT, lambda *_: daemon.stop())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: daemon.stop())
    daemon.start()


if __name__ == "__main__":
    main()
