#!/usr/bin/env python3
"""
hushctl - command-line client for the scx_hush daemon (PRD §9.3).

Talks newline-delimited JSON to hushd over a Unix socket (/run/hush.sock,
override with --socket or $HUSH_SOCK). The simulator daemon (daemon/hushd.py)
speaks the same protocol; on platforms without AF_UNIX it listens on TCP,
selected with --tcp PORT or $HUSH_TCP.

    hushctl status
    hushctl class <pid>
    hushctl promote <pid|cgroup>     hushctl demote <pid|cgroup>
    hushctl reset <pid|cgroup>       hushctl reload
    hushctl selftest                 hushctl trace start|stop [file]
"""

import argparse
import json
import os
import socket
import sys

DEFAULT_SOCK = "/run/hush.sock"
DEFAULT_TCP_PORT = 19890  # simulator fallback


class HushctlError(Exception):
    pass


def _connect(sock_path=None, port=None, timeout=5.0):
    if port is None and os.environ.get("HUSH_TCP"):
        port = int(os.environ["HUSH_TCP"])
    if port is None and not hasattr(socket, "AF_UNIX"):
        port = DEFAULT_TCP_PORT
    if port is not None:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        return s, f"127.0.0.1:{port}"
    path = sock_path or os.environ.get("HUSH_SOCK") or DEFAULT_SOCK
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    return s, path


def send_command(cmd, args=None, port=None, sock_path=None, timeout=5.0):
    """Send one request and return the decoded reply."""
    req = json.dumps({"cmd": cmd, "args": args or {}}) + "\n"
    try:
        s, where = _connect(sock_path, port, timeout)
    except (FileNotFoundError, ConnectionRefusedError) as e:
        raise HushctlError(
            f"cannot reach hushd ({e.strerror or e}); is it running? "
            "Start it with: sudo hushd --policy policy.toml"
        ) from e
    except PermissionError as e:
        raise HushctlError(f"permission denied on the control socket: {e}") from e
    with s:
        s.sendall(req.encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    if not buf:
        raise HushctlError(f"hushd at {where} closed the connection without replying")
    return json.loads(buf.decode())


# ----------------------------------------------------------------- output


def _ms(ns):
    return ns / 1e6


def print_status(r):
    classes = r.get("classes", {})
    c = r.get("counters", {})
    feats = r.get("features", {})
    cfg = r.get("config", {})
    print(f"scx_hush {r.get('version', '')} [{r.get('backend', '?')}]  "
          f"sched_ext: {r.get('sched_ext_state', '?')}"
          + (f" ({r['ops']})" if r.get("ops") else ""))
    print(f"policy {r.get('policy', '')}  generation {r.get('policy_gen')}  "
          f"uptime {r.get('uptime_s', 0)}s  cgroups classified {r.get('cgroups_classified', 0)}  "
          f"overrides {r.get('pid_overrides', 0)} pid / {r.get('cgroup_overrides', 0)} cgroup")
    if cfg:
        print(f"slices fg/normal/bg {cfg.get('fg_slice_ms')}/{cfg.get('normal_slice_ms')}/"
              f"{cfg.get('bg_slice_ms')} ms  guard {cfg.get('guard_ms')} ms  "
              f"watchdog {cfg.get('watchdog_ms')} ms  boost {cfg.get('boost_ms')} ms "
              f"(cap {cfg.get('boost_cap_pct')}%)")
    print()
    print(f"  {'class':<11} {'runtime s':>10} {'runs':>10} {'mean wait ms':>13} {'max wait ms':>12}")
    for name in ("FOREGROUND", "NORMAL", "BACKGROUND"):
        k = classes.get(name, {})
        runs = k.get("runs", 0)
        mean = _ms(k.get("wait_ns", 0) / runs) if runs else 0.0
        print(f"  {name:<11} {k.get('runtime_ns', 0) / 1e9:>10.2f} {runs:>10} "
              f"{mean:>13.3f} {_ms(k.get('wait_max_ns', 0)):>12.3f}")
    print()
    boosts = sum(c.get(f"boosts_{s}", 0) for s in ("hint", "pi", "glibc", "fallback"))
    print(f"  preemption kicks {c.get('preempt_kicks', 0)}   tick yields {c.get('tick_yields', 0)}")
    print(f"  guard firings    {c.get('guard_firings', 0)} bg / {c.get('guard_normal', 0)} normal"
          f"   hard guard {c.get('hard_guard_firings', 0)}")
    print(f"  boosts           {boosts} (hint {c.get('boosts_hint', 0)}, pi {c.get('boosts_pi', 0)}, "
          f"glibc {c.get('boosts_glibc', 0)}, fallback {c.get('boosts_fallback', 0)})"
          f"   renewals {c.get('boost_renewals', 0)}   capped {c.get('boost_capped', 0)}")
    print(f"  hint abuse       {c.get('hint_abuse', 0)}   d-state escapes {c.get('dstate_escapes', 0)}"
          f"   reclassifications {c.get('reclassify', 0)}")
    if feats:
        on = [k for k, v in feats.items() if v]
        off = [k for k, v in feats.items() if not v]
        print(f"  features on: {', '.join(on) or '-'}   off: {', '.join(off) or '-'}")


def print_class(r):
    rows = [
        ("pid", r.get("pid")), ("tgid", r.get("tgid")), ("comm", r.get("comm")),
        ("cgroup", r.get("cgroup")), ("uid", r.get("uid")),
        ("policy class", f"{r.get('policy_class')} ({r.get('policy_match')})"),
        ("matched", r.get("rule")),
        ("base class", r.get("base_class")),
        ("effective class", r.get("effective_class")),
        ("reason", r.get("reason")),
    ]
    if r.get("boost_source"):
        rows.append(("boost", f"{r['boost_source']}, {r.get('boost_remaining_us', 0)} us left"))
    if r.get("crit_depth"):
        rows.append(("hint depth", r["crit_depth"]))
    for k, v in rows:
        if v is not None:
            print(f"{k + ':':<17}{v}")


def print_selftest(r):
    for c in r.get("checks", []):
        tag = "PASS" if c["ok"] else ("FAIL" if c.get("fatal") else "WARN")
        print(f"  [{tag}] {c['name']:<20} {c.get('detail', '')}")
    print(f"tier 3 (glibc mutex) detection: {'enabled' if r.get('tier3_enabled') else 'disabled'}")
    print(r.get("verdict", ""))


# ----------------------------------------------------------------- main


def build_parser():
    p = argparse.ArgumentParser(prog="hushctl", description="Control the scx_hush scheduler.")
    p.add_argument("--socket", help=f"control socket (default $HUSH_SOCK or {DEFAULT_SOCK})")
    p.add_argument("--tcp", type=int, metavar="PORT", help="connect to a simulator daemon over TCP")
    p.add_argument("--json", action="store_true", help="print the raw JSON reply")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="per-class runtime, waits, preemptions, guard firings, boosts")
    s = sub.add_parser("class", help="a task's class and why")
    s.add_argument("pid", type=int)
    for name, hlp in (("promote", "move to FOREGROUND until demoted, reset or exit"),
                      ("demote", "move to BACKGROUND"),
                      ("reset", "drop a promote/demote override")):
        s = sub.add_parser(name, help=hlp)
        s.add_argument("target", help="PID or cgroup path such as /user.slice/build.scope")
    sub.add_parser("reload", help="re-read the policy file and bump the policy generation")
    sub.add_parser("selftest", help="check kernel support and the glibc layout tier 3 needs")
    s = sub.add_parser("trace", help="record per-task wakeup latency to CSV")
    s.add_argument("action", choices=["start", "stop"])
    s.add_argument("file", nargs="?", default="hush-trace.csv")
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    args = {}
    if a.command == "class":
        args = {"pid": a.pid}
    elif a.command in ("promote", "demote", "reset"):
        args = {"target": a.target}
    elif a.command == "trace":
        # hushd runs elsewhere; give it an absolute path.
        args = {"action": a.action, "file": os.path.abspath(a.file)}

    try:
        r = send_command(a.command, args, port=a.tcp, sock_path=a.socket)
    except HushctlError as e:
        print(f"hushctl: {e}", file=sys.stderr)
        return 1

    if a.json:
        print(json.dumps(r, indent=2))
    elif r.get("status") != "ok":
        print(f"hushctl: {r.get('message', 'error')}", file=sys.stderr)
        return 1
    elif a.command == "status":
        print_status(r)
    elif a.command == "class":
        print_class(r)
    elif a.command == "selftest":
        print_selftest(r)
    else:
        print(r.get("message", "ok"))
    return 0 if r.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
