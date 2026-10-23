#!/usr/bin/env python3
"""
Real evaluation harness for scx_hush (PRD §12).

Runs each experiment against the baselines on this machine and writes raw
output, a tidy CSV of metrics and a meta.json (policy used, uname -a, git
commit, CPU governor, arguments) per invocation (NFR-10).

    sudo bench/real/run.py --experiment E1 --reps 5 --duration 120 --warmup 30
    bench/real/run.py --experiment all --dry-run        # print the matrix only

Baselines (§12.1)
    B0  foreground alone              B4  background cgroup with cpu.idle = 1
    B1  default scheduler (EEVDF)     B5  scx_hush, inversion handling off
    B2  background at nice 19         B6  scx_hush, full
    B3  background SCHED_IDLE

Foreground work runs in /hush-bench/fg and background work in /hush-bench/bg,
with the cpu controller off unless B4 needs cpu.idle. Background progress is
the CPU time that /hush-bench/bg consumed while foreground was measured
(cgroup cpu.stat), which works for any background command.

Needs root, a cgroup v2 hierarchy and the workload tools: schbench, zstd,
stress-ng (fallback background), pgbench/psql (E3), perf or hackbench (E7).
B5/B6 also need a sched_ext kernel and build/hushd.
"""

import argparse
import csv
import json
import os
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cli.hushctl import HushctlError, send_command  # noqa: E402

BUILD = ROOT / "build"
HUSHD = BUILD / "hushd"
TOOLS = BUILD / "tools"
POLICY = Path(__file__).with_name("policy.bench.toml")
def _cgroup2_root() -> Path:
    try:
        for line in open("/proc/self/mounts"):
            dev, mnt, fstype = line.split()[:3]
            if fstype == "cgroup2":
                return Path(mnt)
    except OSError:
        pass
    return Path("/sys/fs/cgroup")


CG_ROOT = _cgroup2_root()
CG_BENCH = CG_ROOT / "hush-bench"
DRY = False
NPROC = os.cpu_count() or 1

CONFIGS = ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]


@dataclass
class Experiment:
    id: str
    question: str
    workload: str
    configs: List[str]
    metric: str
    params: Dict = field(default_factory=dict)


# §12.3
EXPERIMENTS = {
    "E1": Experiment("E1", "Is foreground isolated?", "laptop", CONFIGS,
                     "schbench p99 and p99.9 wakeup latency"),
    "E2": Experiment("E2", "Does control-loop jitter stay low?", "robot", CONFIGS,
                     "p99 and max period deviation"),
    "E3": Experiment("E3", "Do we reproduce UFS's database result?", "database",
                     ["B1", "B3", "B6"], "throughput and p99 transaction latency"),
    "E4": Experiment("E4", "Does background still progress?", "laptop+robot",
                     ["B1", "B2", "B3", "B4", "B5", "B6"], "background CPU seconds per minute"),
    "E5": Experiment("E5", "Does inversion handling work?", "inversion", ["B5", "B6"],
                     "time FG stays blocked per acquisition, per mutex type"),
    "E6": Experiment("E6", "Which guard interval is right?", "laptop", ["B6"],
                     "p99 FG latency vs longest BG wait",
                     {"guard_ms": [500, 1000, 2000, 4000]}),
    "E7": Experiment("E7", "What does the scheduler cost?", "overhead", ["B1", "B6"],
                     "throughput and latency delta with no background"),
    "E8": Experiment("E8", "Is it stable?", "soak", ["B6"], "watchdog aborts in a 24-hour soak"),
    "E9": Experiment("E9", "Does it hold on embedded hardware?", "robot", ["B1", "B3", "B6"],
                     "p99 jitter (run on a Raspberry Pi 5 or Jetson)"),
}


# --------------------------------------------------------------- utilities


class Skip(Exception):
    """A run cannot happen on this machine (missing tool, no sched_ext...)."""


def need(tool: str) -> str:
    path = shutil.which(tool)
    if path:
        return path
    if DRY:
        return f"{tool}(missing)"
    raise Skip(f"{tool} not installed")


def sh(cmd, **kw) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, **kw).stdout.strip()


def percentile(xs: List[float], p: float) -> float:
    if not xs:
        return float("nan")
    s = sorted(xs)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def bootstrap_ci(xs: List[float], seed: int, n: int = 2000):
    """Median and 95% CI of the median (§12.4)."""
    if not xs:
        return float("nan"), float("nan"), float("nan")
    rng = random.Random(seed)
    meds = sorted(statistics.median(rng.choices(xs, k=len(xs))) for _ in range(n))
    return statistics.median(xs), meds[int(0.025 * n)], meds[int(0.975 * n) - 1]


# --------------------------------------------------------------- cgroups


class Cgroups:
    """/hush-bench/{fg,bg,mixed}; cpu controller only for B4."""

    def __init__(self, dry: bool):
        self.dry = dry

    def setup(self, config: str):
        if self.dry:
            return
        if not (CG_ROOT / "cgroup.controllers").exists():
            raise Skip(f"no cgroup v2 hierarchy at {CG_ROOT}")
        CG_BENCH.mkdir(exist_ok=True)
        for d in ("fg", "bg", "mixed"):
            (CG_BENCH / d).mkdir(exist_ok=True)
        want_cpu = config == "B4"
        if want_cpu:
            self._write(CG_ROOT / "cgroup.subtree_control", "+cpu")
        if want_cpu or "cpu" in (CG_BENCH / "cgroup.subtree_control").read_text().split():
            self._write(CG_BENCH / "cgroup.subtree_control", "+cpu" if want_cpu else "-cpu")
        if want_cpu:
            self._write(CG_BENCH / "bg" / "cpu.idle", "1")

    def teardown(self):
        if self.dry or not CG_BENCH.exists():
            return
        for d in ("fg", "bg", "mixed"):
            p = CG_BENCH / d
            if p.exists():
                for pid in (p / "cgroup.procs").read_text().split():
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def remove(self):
        if self.dry or not CG_BENCH.exists():
            return
        self.teardown()
        time.sleep(0.2)
        for d in ("fg", "bg", "mixed", ""):
            try:
                (CG_BENCH / d).rmdir()
            except OSError:
                pass

    @staticmethod
    def _write(path: Path, val: str):
        try:
            path.write_text(val)
        except OSError as e:
            raise Skip(f"cannot write {val!r} to {path}: {e}")

    @staticmethod
    def usage_usec(group: str) -> int:
        for line in (CG_BENCH / group / "cpu.stat").read_text().splitlines():
            k, v = line.split()
            if k == "usage_usec":
                return int(v)
        return 0


def launcher(group: str, config: str, background: bool):
    """preexec_fn: join the cgroup, then apply the baseline's priority knob."""

    def pre():
        if CG_BENCH.exists():
            (CG_BENCH / group / "cgroup.procs").write_text(str(os.getpid()))
        if background and config == "B2":
            os.nice(19)
        if background and config == "B3":
            os.sched_setscheduler(0, os.SCHED_IDLE, os.sched_param(0))
        os.setsid()

    return pre


# --------------------------------------------------------------- hushd


class Hushd:
    """Runs build/hushd for B5/B6 and checks it is still loaded at the end."""

    def __init__(self, outdir: Path, dry: bool, log):
        self.outdir, self.dry, self.log = outdir, dry, log
        self.proc: Optional[subprocess.Popen] = None
        self.sock = str(outdir / "hush.sock")

    def start(self, config: str, guard_ms: Optional[int] = None) -> Path:
        policy = POLICY.read_text()
        if guard_ms is not None:
            policy = policy.replace("guard_ms        = 2000", f"guard_ms        = {guard_ms}")
        policy = policy.replace("[scheduler]",
                                f"[scheduler]\nlibhush_path = \"{BUILD / 'libhush.so'}\"", 1)
        used = self.outdir / f"policy.{config}{'' if guard_ms is None else f'.g{guard_ms}'}.toml"
        used.write_text(policy)
        cmd = [str(HUSHD), "--policy", str(used), "--socket", self.sock]
        if config == "B5":
            cmd.append("--no-inversion")
        self.log(f"    hushd: {' '.join(cmd)}")
        if self.dry:
            return used
        if not HUSHD.exists():
            raise Skip("build/hushd missing (run make)")
        if not Path("/sys/kernel/sched_ext").exists():
            raise Skip("kernel has no sched_ext (CONFIG_SCHED_CLASS_EXT)")
        log = open(self.outdir / f"hushd.{config}.log", "a")
        self.proc = subprocess.Popen(cmd, stdout=log, stderr=log)
        for _ in range(100):
            if Path(self.sock).exists():
                try:
                    send_command("ping", sock_path=self.sock)
                    break
                except (HushctlError, OSError):
                    pass
            if self.proc.poll() is not None:
                raise Skip(f"hushd exited at start; see {log.name}")
            time.sleep(0.1)
        return used

    def status(self) -> dict:
        if self.dry or not self.proc:
            return {}
        try:
            return send_command("status", sock_path=self.sock)
        except (HushctlError, OSError):
            return {}

    def stop(self) -> Optional[int]:
        """Returns hushd's exit code (non-zero: the kernel aborted the scheduler)."""
        if not self.proc:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
        try:
            rc = self.proc.wait(20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.wait()
        self.proc = None
        return rc


# --------------------------------------------------------------- workloads


class Run:
    """One (experiment, config, rep) execution."""

    def __init__(self, h: "Harness", exp: Experiment, config: str, rep: int, extra: Dict):
        self.h, self.exp, self.config, self.rep, self.extra = h, exp, config, rep, extra
        tag = "_".join([exp.id, config] + [f"{k}{v}" for k, v in extra.items()] + [f"r{rep}"])
        self.tag = tag
        self.raw = h.outdir / "raw"
        self.bg: List[subprocess.Popen] = []
        self.metrics: Dict[str, float] = {}

    # Helpers ----------------------------------------------------------

    def spawn(self, cmd, group, background, **kw) -> Optional[subprocess.Popen]:
        self.h.log(f"    {'bg' if background else 'fg'}: {' '.join(map(str, cmd))}")
        if self.h.dry:
            return None
        return subprocess.Popen([str(c) for c in cmd], preexec_fn=launcher(group, self.config, background),
                                stdout=kw.pop("stdout", subprocess.DEVNULL),
                                stderr=kw.pop("stderr", subprocess.DEVNULL), **kw)

    def start_bg(self, cmds):
        if self.config == "B0":
            return
        for c in cmds:
            p = self.spawn(c, "bg", True)
            if p:
                self.bg.append(p)

    def stop_bg(self):
        for p in self.bg:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        self.bg.clear()

    def run_fg(self, cmd, group="fg", timeout=None) -> str:
        out = self.raw / f"{self.tag}.fg.txt"
        if self.h.dry:
            self.spawn(cmd, group, False)
            return ""
        with open(out, "w") as f:
            p = self.spawn(cmd, group, False, stdout=f, stderr=subprocess.STDOUT)
            p.wait(timeout=timeout)
        return out.read_text()

    def bg_window(self, measure):
        """Warm up with background load, then measure foreground; record BG CPU."""
        self.h.log(f"    warm-up {self.h.args.warmup}s")
        if not self.h.dry:
            time.sleep(self.h.args.warmup if self.config != "B0" else 0)
        u0 = 0 if self.h.dry else Cgroups.usage_usec("bg")
        t0 = time.monotonic()
        measure()
        dt = time.monotonic() - t0
        if not self.h.dry and dt > 0:
            self.metrics["bg_cpu_s_per_min"] = (Cgroups.usage_usec("bg") - u0) / 1e6 * 60 / dt

    # Workloads --------------------------------------------------------

    def laptop(self):
        schbench = need("schbench")
        build = os.environ.get("HUSH_BUILD_CMD")
        if build:
            bg = [["sh", "-c", f"while :; do {build}; done"]]
        else:
            bg = [[need("stress-ng"), "--cpu", NPROC, "--cpu-method", "matrixprod"]]
        self.start_bg(bg)
        d = self.h.args.duration

        def measure():
            out = self.run_fg([schbench, "-m", 2, "-t", max(1, NPROC // 2), "-r", d])
            self.metrics.update(parse_schbench(out))
        self.bg_window(measure)

    def robot(self):
        loop = TOOLS / "periodic_loop"
        if not loop.exists() and not self.h.dry:
            raise Skip("build/tools/periodic_loop missing (run make)")
        blob = self.h.blob()
        bg = [["sh", "-c", f"while :; do {need('zstd')} -q -19 -T0 -f {blob} -o /dev/null; done"]]
        if shutil.which("rsync"):
            dst = self.h.outdir / "rsync-dst"
            bg.append(["sh", "-c", f"while :; do rsync -a --inplace {blob} {dst}; rm -f {dst}; done"])
        self.start_bg(bg)
        csv_out = self.raw / f"{self.tag}.jitter.csv"

        def measure():
            self.run_fg([loop, "--hz", 100, "--duration", self.h.args.duration, "--work-us", 500,
                         "--out", csv_out])
            if not self.h.dry:
                self.metrics.update(parse_jitter(csv_out))
        self.bg_window(measure)

    def database(self):
        pgbench, psql = need("pgbench"), need("psql")
        db = os.environ.get("PGDATABASE", "hushbench")
        if not self.h.dry and subprocess.run([psql, "-d", db, "-qc", "select 1"],
                                             capture_output=True).returncode:
            raise Skip(f"PostgreSQL database {db} unreachable; run pgbench -i -s 100 {db}")
        # Background sessions run in PostgreSQL backends, outside our cgroups:
        # find each backend's pid and apply the baseline to that process.
        if self.config != "B0":
            for sql in ("VACUUM FULL pgbench_accounts",
                        "SELECT count(*), avg(abalance) FROM pgbench_accounts"):
                self.bg_backend(psql, db, sql)
        log_prefix = self.raw / f"{self.tag}.pgbench"

        def measure():
            out = self.run_fg([pgbench, "-d", db, "-c", 8, "-j", 4, "-T", self.h.args.duration,
                               "-l", "--log-prefix", log_prefix])
            if not self.h.dry:
                self.metrics.update(parse_pgbench(out, log_prefix))
        self.bg_window(measure)

    def bg_backend(self, psql, db, sql):
        self.h.log(f"    bg backend: {sql}")
        if self.h.dry:
            return
        p = subprocess.Popen([psql, "-d", db, "-qAt"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        p.stdin.write("SELECT pg_backend_pid();\n")
        p.stdin.flush()
        pid = int(p.stdout.readline())
        if self.config == "B2":
            os.setpriority(os.PRIO_PROCESS, pid, 19)
        elif self.config == "B3":
            os.sched_setscheduler(pid, os.SCHED_IDLE, os.sched_param(0))
        elif self.config == "B4":
            (CG_BENCH / "bg" / "cgroup.procs").write_text(str(pid))
        elif self.config in ("B5", "B6"):
            send_command("demote", {"target": str(pid)}, sock_path=self.h.hushd.sock)
        p.stdin.write(f"{sql} \\watch 0.1\n")
        p.stdin.flush()
        self.bg.append(p)

    def inversion(self):
        micro = TOOLS / "inversion_micro"
        if not micro.exists() and not self.h.dry:
            raise Skip("build/tools/inversion_micro missing (run make)")
        for mutex in ("pi", "glibc", "hinted"):
            csv_out = self.raw / f"{self.tag}.{mutex}.csv"
            self.run_fg([micro, "--mutex", mutex, "--duration", self.h.args.duration,
                         "--hold-ms", 5, "--load", max(0, NPROC - 1), "--out", csv_out],
                        group="mixed")
            if not self.h.dry:
                xs = [int(r["blocked_ns"]) / 1e6 for r in csv.DictReader(open(csv_out))]
                self.metrics[f"{mutex}_blocked_mean_ms"] = statistics.fmean(xs) if xs else float("nan")
                self.metrics[f"{mutex}_blocked_p99_ms"] = percentile(xs, 99)
                self.metrics[f"{mutex}_blocked_max_ms"] = max(xs) if xs else float("nan")

    def overhead(self):
        schbench = need("schbench")
        out = self.run_fg([schbench, "-m", 2, "-t", max(1, NPROC // 2), "-r", self.h.args.duration])
        self.metrics.update(parse_schbench(out))
        if shutil.which("perf"):
            cmd = ["perf", "bench", "sched", "messaging", "-g", 10, "-l", 2000]
        else:
            cmd = [need("hackbench"), "-g", 10, "-l", 2000]
        out = self.run_fg(cmd)
        for line in out.splitlines():
            if "Total time" in line or line.startswith("Time:"):
                self.metrics["hackbench_s"] = float(line.split(":")[1].split()[0])

    def soak(self):
        end = time.monotonic() + self.h.args.soak_hours * 3600
        cycle = 0
        while self.h.dry or time.monotonic() < end:
            for w in (self.laptop, self.robot, self.inversion):
                self.h.log(f"    soak cycle {cycle}: {w.__name__}")
                try:
                    w()
                finally:
                    self.stop_bg()
                if self.h.hushd.proc and self.h.hushd.proc.poll() is not None:
                    self.metrics["aborted"] = 1
                    return
            cycle += 1
            if self.h.dry:
                break
        self.metrics["soak_cycles"] = cycle

    def execute(self):
        workload = self.exp.workload
        if workload == "laptop+robot":
            workload = self.extra.get("w", "laptop")
        fn = {"laptop": self.laptop, "robot": self.robot, "database": self.database,
              "inversion": self.inversion, "overhead": self.overhead, "soak": self.soak}[workload]
        try:
            fn()
        finally:
            self.stop_bg()


# --------------------------------------------------------------- parsers


def parse_schbench(out: str) -> Dict[str, float]:
    """Last 'Wakeup Latencies' block of schbench output, in microseconds."""
    m: Dict[str, float] = {}
    block = out.rsplit("Wakeup Latencies", 1)[-1] if "Wakeup Latencies" in out else out
    block = block.split("Request Latencies", 1)[0]
    for line in block.splitlines():
        line = line.strip().lstrip("*").strip()
        if "th:" in line:
            pct, rest = line.split("th:", 1)
            try:
                m[f"wakeup_p{pct.strip()}_us"] = float(rest.split()[0])
            except (ValueError, IndexError):
                pass
    if "RPS" in out:
        for line in out.splitlines():
            if "average rps" in line.lower():
                m["rps"] = float(line.split(":")[-1].split()[0])
    return m


def parse_jitter(path: Path) -> Dict[str, float]:
    rows = list(csv.DictReader(open(path)))[1:]  # first period has no predecessor
    dev = [abs(int(r["period_dev_ns"])) / 1e3 for r in rows]
    late = [int(r["wake_late_ns"]) / 1e3 for r in rows]
    return {"period_dev_p99_us": percentile(dev, 99), "period_dev_max_us": max(dev, default=0),
            "wake_late_p99_us": percentile(late, 99), "wake_late_max_us": max(late, default=0)}


def parse_pgbench(out: str, prefix: Path) -> Dict[str, float]:
    m: Dict[str, float] = {}
    for line in out.splitlines():
        if line.startswith("tps ="):
            m["tps"] = float(line.split()[2])
    lat = []
    for f in prefix.parent.glob(prefix.name + "*"):
        for line in open(f):
            parts = line.split()
            if len(parts) >= 3:
                lat.append(int(parts[2]) / 1e3)
    if lat:
        m["txn_p99_ms"] = percentile(lat, 99)
        m["txn_p50_ms"] = percentile(lat, 50)
    return m


# --------------------------------------------------------------- harness


class Harness:
    def __init__(self, args):
        self.args = args
        self.dry = args.dry_run
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.outdir = Path(args.out or (Path(__file__).parent / "results" / stamp))
        (self.outdir / "raw").mkdir(parents=True, exist_ok=True)
        self.cg = Cgroups(self.dry)
        self.hushd = Hushd(self.outdir, self.dry, self.log)
        self.rows: List[dict] = []
        self.logf = open(self.outdir / "run.log", "a")
        self._governors: Dict[Path, str] = {}

    def log(self, msg: str):
        print(msg)
        self.logf.write(msg + "\n")
        self.logf.flush()

    def blob(self) -> Path:
        """A fixed-seed 256 MiB file for compression/copy background load."""
        p = self.outdir / "blob.bin"
        if not p.exists() and not self.dry:
            rng = random.Random(self.args.seed)
            with open(p, "wb") as f:
                for _ in range(256):
                    # Half random, half repetitive: compressible but not trivial.
                    f.write(rng.randbytes(512 * 1024) + bytes(512 * 1024))
        return p

    def write_meta(self, exps):
        meta = {
            "experiments": [e.id for e in exps],
            "args": vars(self.args),
            "uname": sh(["uname", "-a"]),
            "git_commit": sh(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
            "git_dirty": bool(sh(["git", "-C", str(ROOT), "status", "--porcelain"])),
            "nproc": NPROC,
            "governor": sh(["cat", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"]),
            "sched_ext_state": sh(["cat", "/sys/kernel/sched_ext/state"]),
            "policy": POLICY.read_text(),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "dry_run": self.dry,
        }
        (self.outdir / "meta.json").write_text(json.dumps(meta, indent=2))

    def pin_frequency(self):
        """§12.4: performance governor, turbo off; restored on exit."""
        if self.dry or not self.args.pin_freq:
            return
        for g in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor"):
            self._governors[g] = g.read_text().strip()
            g.write_text("performance")
        for t, off in ((Path("/sys/devices/system/cpu/intel_pstate/no_turbo"), "1"),
                       (Path("/sys/devices/system/cpu/cpufreq/boost"), "0")):
            if t.exists():
                self._governors[t] = t.read_text().strip()
                t.write_text(off)

    def restore_frequency(self):
        for p, v in self._governors.items():
            try:
                p.write_text(v)
            except OSError:
                pass

    def plan(self, exp: Experiment):
        """(config, extra) pairs to run for @exp."""
        configs = [c for c in exp.configs if not self.args.configs or c in self.args.configs]
        if exp.id == "E6":
            return [(c, {"guard": g}) for c in configs for g in exp.params["guard_ms"]]
        if exp.id == "E4":
            return [(c, {"w": w}) for c in configs for w in ("laptop", "robot")]
        return [(c, {}) for c in configs]

    def run_one(self, exp: Experiment, config: str, rep: int, extra: Dict):
        run = Run(self, exp, config, rep, extra)
        self.log(f"[{run.tag}] {exp.question}")
        status, rc = "ok", None
        try:
            self.cg.setup(config)
            if config in ("B5", "B6"):
                self.hushd.start(config, extra.get("guard"))
            run.execute()
            st = self.hushd.status()
            if st:
                bg = st.get("classes", {}).get("BACKGROUND", {})
                run.metrics["bg_wait_max_ms"] = bg.get("wait_max_ns", 0) / 1e6
                for k in ("guard_firings", "hard_guard_firings", "preempt_kicks", "boosts_pi",
                          "boosts_glibc", "boosts_hint", "boosts_fallback", "hint_abuse"):
                    run.metrics[k] = st.get("counters", {}).get(k, 0)
        except Skip as e:
            status = f"skipped: {e}"
        except subprocess.TimeoutExpired:
            status = "timeout"
        finally:
            rc = self.hushd.stop()
            self.cg.teardown()
        if rc:
            status = f"hushd exited {rc} (scheduler aborted?)"
            run.metrics["aborted"] = 1
        self.log(f"    -> {status} {json.dumps(run.metrics)}")
        for k, v in run.metrics.items():
            self.rows.append({"experiment": exp.id, "config": config, "rep": rep,
                              **{f"x_{a}": b for a, b in extra.items()},
                              "metric": k, "value": v, "status": status})
        if not run.metrics:
            self.rows.append({"experiment": exp.id, "config": config, "rep": rep,
                              **{f"x_{a}": b for a, b in extra.items()},
                              "metric": "", "value": "", "status": status})

    def save(self):
        if not self.rows:
            return
        keys = sorted({k for r in self.rows for k in r}, key=lambda k: (
            ["experiment", "config", "rep"].index(k) if k in ("experiment", "config", "rep") else 3, k))
        with open(self.outdir / "metrics.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(self.rows)
        # Median and 95% bootstrap CI over reps.
        groups: Dict[tuple, List[float]] = {}
        for r in self.rows:
            if r["metric"] and isinstance(r["value"], (int, float)):
                extra = tuple(sorted((k, r[k]) for k in r if k.startswith("x_")))
                groups.setdefault((r["experiment"], r["config"], extra, r["metric"]), []).append(r["value"])
        with open(self.outdir / "summary.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["experiment", "config", "extra", "metric", "n", "median", "ci_lo", "ci_hi"])
            for (e, c, extra, m), xs in sorted(groups.items()):
                med, lo, hi = bootstrap_ci(xs, self.args.seed)
                w.writerow([e, c, ";".join(f"{k[2:]}={v}" for k, v in extra), m, len(xs), med, lo, hi])

    def main(self):
        ids = list(EXPERIMENTS) if self.args.experiment == "all" else self.args.experiment.split(",")
        exps = [EXPERIMENTS[i.upper()] for i in ids]
        if not self.dry and os.geteuid() != 0:
            sys.exit("run.py needs root (cgroups, SCHED_IDLE, hushd); use --dry-run to preview")
        random.seed(self.args.seed)
        self.write_meta(exps)
        shutil.copy(POLICY, self.outdir / POLICY.name)
        self.pin_frequency()
        try:
            for exp in exps:
                for config, extra in self.plan(exp):
                    reps = 1 if exp.id == "E8" else self.args.reps
                    for rep in range(reps):
                        self.run_one(exp, config, rep, extra)
                        self.save()
        finally:
            self.restore_frequency()
            self.cg.remove()
            self.save()
        self.log(f"results in {self.outdir}")


def main(argv=None):
    p = argparse.ArgumentParser(description="scx_hush evaluation harness (PRD §12)")
    p.add_argument("--experiment", "-e", default="E1", help="E1..E9, comma-separated, or 'all'")
    p.add_argument("--configs", type=lambda s: s.split(","), help="subset of B0..B6")
    p.add_argument("--reps", type=int, default=5)
    p.add_argument("--duration", type=int, default=120, help="measured seconds per run")
    p.add_argument("--warmup", type=int, default=30, help="background warm-up seconds")
    p.add_argument("--soak-hours", type=float, default=24.0, help="E8 duration")
    p.add_argument("--seed", type=int, default=20261022)
    p.add_argument("--pin-freq", action="store_true", help="performance governor, turbo off")
    p.add_argument("--out", help="output directory (default bench/real/results/<timestamp>)")
    p.add_argument("--dry-run", action="store_true", help="print the plan, run nothing")
    args = p.parse_args(argv)
    global DRY
    DRY = args.dry_run
    Harness(args).main()


if __name__ == "__main__":
    main()
