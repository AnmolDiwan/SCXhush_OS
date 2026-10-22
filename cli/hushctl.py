#!/usr/bin/env python3
"""
hushctl - Command-line interface for scx_hush
Implements PRD Section 9.3 (FR-5, FR-18, FR-19).
"""

import sys
import json
import socket
import argparse

DEFAULT_PORT = 19890


def send_command(cmd: str, args: dict, port: int = DEFAULT_PORT) -> dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", port))
        req = json.dumps({"cmd": cmd, "args": args})
        s.sendall(req.encode("utf-8"))
        res = s.recv(8192).decode("utf-8").strip()
        s.close()
        return json.loads(res)
    except ConnectionRefusedError:
        print("[hushctl] Error: Could not connect to hushd daemon. Is hushd running?", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[hushctl] Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_status(args):
    resp = send_command("status", {})
    if resp.get("status") == "ok":
        print("==================================================")
        print("          scx_hush Scheduler Status               ")
        print("==================================================")
        print(f"Policy Generation: {resp.get('policy_gen')}")
        print(f"Starvation Guard Firings: {resp.get('guard_firings')}")
        print(f"Inversion Boosts:        {resp.get('boost_count')}")
        print(f"Hint Abuse Rejections:   {resp.get('hint_abuse_count')}")
        print("--------------------------------------------------")
        print("Per-Class Metrics:")
        runtimes = resp.get("runtime_sec", {})
        waits = resp.get("wait_sec", {})
        preempts = resp.get("preemptions", {})
        for cls in ("FOREGROUND", "NORMAL", "BACKGROUND"):
            r = runtimes.get(cls, 0.0)
            w = waits.get(cls, 0.0)
            p = preempts.get(cls, 0)
            print(f"  [{cls:<10}] Runtime: {r:8.3f}s | Wait: {w:8.3f}s | Preemptions: {p:5d}")
        print("==================================================")
    else:
        print(f"Error: {resp.get('message')}")


def cmd_class(args):
    resp = send_command("class", {"pid": args.pid})
    if resp.get("status") == "ok":
        print(f"PID:             {resp['pid']}")
        print(f"Comm:            {resp['comm']}")
        print(f"Cgroup:          {resp['cgroup']}")
        print(f"Base Class:      {resp['base_class']}")
        print(f"Effective Class: {resp['effective_class']}")
        print(f"Reason:          {resp['reason']}")
        if resp.get("crit_depth", 0) > 0:
            print(f"Critical Depth:  {resp['crit_depth']} (libhush hint active)")
    else:
        print(f"Error: {resp.get('message')}")


def cmd_promote(args):
    resp = send_command("promote", {"target": args.target})
    if resp.get("status") == "ok":
        print(f"[hushctl] {resp.get('message')}")
    else:
        print(f"Error: {resp.get('message')}")


def cmd_demote(args):
    resp = send_command("demote", {"target": args.target})
    if resp.get("status") == "ok":
        print(f"[hushctl] {resp.get('message')}")
    else:
        print(f"Error: {resp.get('message')}")


def cmd_reload(args):
    resp = send_command("reload", {})
    if resp.get("status") == "ok":
        print(f"[hushctl] Policy reloaded successfully (Generation: {resp.get('policy_gen')})")
    else:
        print(f"Error: {resp.get('message')}")


def cmd_selftest(args):
    resp = send_command("selftest", {})
    if resp.get("status") == "ok":
        print("Running scx_hush compatibility selftest...")
        tests = resp.get("tests", {})
        for test_name, passed in tests.items():
            status_str = "PASS" if passed else "FAIL"
            print(f"  [{status_str}] {test_name}")
        print(f"Result: {resp.get('verdict')}")
    else:
        print(f"Error: {resp.get('message')}")


def cmd_trace(args):
    resp = send_command("trace", {"action": args.action, "file": args.file})
    if resp.get("status") == "ok":
        print(f"[hushctl] {resp.get('message')}")
    else:
        print(f"Error: {resp.get('message')}")


def main():
    parser = argparse.ArgumentParser(description="hushctl - scx_hush Control Plane CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    sub_status = subparsers.add_parser("status", help="Show live counters and per-class stats")
    sub_status.set_defaults(func=cmd_status)

    # class <pid>
    sub_class = subparsers.add_parser("class", help="Show a task's class and why")
    sub_class.add_argument("pid", type=int, help="Process ID")
    sub_class.set_defaults(func=cmd_class)

    # promote <pid or cgroup>
    sub_promote = subparsers.add_parser("promote", help="Move task or cgroup to FOREGROUND")
    sub_promote.add_argument("target", help="PID or cgroup path")
    sub_promote.set_defaults(func=cmd_promote)

    # demote <pid or cgroup>
    sub_demote = subparsers.add_parser("demote", help="Move task or cgroup to BACKGROUND")
    sub_demote.add_argument("target", help="PID or cgroup path")
    sub_demote.set_defaults(func=cmd_demote)

    # reload
    sub_reload = subparsers.add_parser("reload", help="Re-read policy file without reload")
    sub_reload.set_defaults(func=cmd_reload)

    # selftest
    sub_selftest = subparsers.add_parser("selftest", help="Validate glibc layout and kernel support")
    sub_selftest.set_defaults(func=cmd_selftest)

    # trace <start|stop> <file>
    sub_trace = subparsers.add_parser("trace", help="Record per-task wakeup latency to CSV")
    sub_trace.add_argument("action", choices=["start", "stop"], help="Start or stop tracing")
    sub_trace.add_argument("file", nargs="?", default="trace.csv", help="Output CSV path")
    sub_trace.set_defaults(func=cmd_trace)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

