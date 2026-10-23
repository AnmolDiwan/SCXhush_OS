#!/usr/bin/env python3
"""
Figures for the scx_hush report (PRD §12.5) from a bench/real/run.py result
directory. A figure whose experiment was not run (or was skipped) is left out.

    bench/real/plot.py bench/real/results/<timestamp>

  fig1_e1_latency_cdf.png     FG wakeup latency CDF per configuration (E1)
  fig2_e2_jitter_box.png      control-loop period deviation per configuration (E2)
  fig3_tradeoff.png           FG p99 vs background progress (E1 + E4)
  fig4_e5_inversion.png       blocked time per acquisition by mutex type, B5 vs B6 (E5)
  fig5_e6_guard_sweep.png     FG p99 and longest BG wait vs guard interval (E6)
"""

import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit("plot.py needs matplotlib: pip install matplotlib")

CONFIG_ORDER = ["B0", "B1", "B2", "B3", "B4", "B5", "B6"]
LABELS = {"B0": "FG alone", "B1": "EEVDF", "B2": "nice 19", "B3": "SCHED_IDLE",
          "B4": "cpu.idle", "B5": "hush (no inv.)", "B6": "hush"}


def load(resdir: Path):
    rows = list(csv.DictReader(open(resdir / "metrics.csv")))
    return [r for r in rows if r["status"] == "ok" and r["metric"]]


def by(rows, exp, metric, key="config"):
    out = defaultdict(list)
    for r in rows:
        if r["experiment"] == exp and r["metric"] == metric:
            out[r[key]].append(float(r["value"]))
    return out


def ordered(d):
    return [c for c in CONFIG_ORDER if c in d]


def fig1(rows, resdir, out):
    """CDF from schbench's percentile points, median across reps."""
    pts = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r["experiment"] == "E1" and r["metric"].startswith("wakeup_p"):
            pct = float(r["metric"][len("wakeup_p"):-len("_us")])
            pts[r["config"]][pct].append(float(r["value"]))
    if not pts:
        return False
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for c in ordered(pts):
        xs = sorted(pts[c])
        ax.step([statistics.median(pts[c][p]) for p in xs], [p / 100 for p in xs],
                where="post", label=LABELS[c], marker=".")
    ax.set_xscale("log")
    ax.set_xlabel("wakeup latency (µs, log)")
    ax.set_ylabel("fraction of wakeups")
    ax.set_title("E1: foreground wakeup latency (schbench)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(out / "fig1_e1_latency_cdf.png", dpi=150)
    return True


def fig2(rows, resdir, out):
    data = defaultdict(list)
    for f in sorted((resdir / "raw").glob("E2_*.jitter.csv")):
        config = f.name.split("_")[1]
        rs = list(csv.DictReader(open(f)))[1:]
        data[config] += [abs(int(r["period_dev_ns"])) / 1e3 for r in rs]
    if not data:
        return False
    cs = ordered(data)
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.boxplot([data[c] for c in cs], showfliers=True, whis=(1, 99))
    ax.set_xticks(range(1, len(cs) + 1), [LABELS[c] for c in cs], rotation=20)
    ax.set_yscale("log")
    ax.set_ylabel("|period deviation| (µs, log); whiskers p1–p99")
    ax.set_title("E2: 100 Hz control-loop jitter")
    ax.grid(alpha=0.3, axis="y")
    fig.tight_layout()
    fig.savefig(out / "fig2_e2_jitter_box.png", dpi=150)
    return True


def fig3(rows, resdir, out):
    p99 = by(rows, "E1", "wakeup_p99.0_us")
    prog = by([r for r in rows if r.get("x_w", "laptop") in ("laptop", "")], "E4", "bg_cpu_s_per_min")
    if not prog:
        prog = by(rows, "E1", "bg_cpu_s_per_min")
    cs = [c for c in ordered(p99) if c in prog]
    if not cs:
        return False
    fig, ax = plt.subplots(figsize=(6, 4.5))
    for c in cs:
        x, y = statistics.median(prog[c]), statistics.median(p99[c])
        ax.scatter(x, y, s=60)
        ax.annotate(LABELS[c], (x, y), textcoords="offset points", xytext=(6, 4), fontsize=9)
    ax.set_xlabel("background CPU-seconds per minute")
    ax.set_ylabel("foreground p99 wakeup latency (µs)")
    ax.set_yscale("log")
    ax.set_title("Trade-off: foreground latency vs background progress")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / "fig3_tradeoff.png", dpi=150)
    return True


def fig4(rows, resdir, out):
    mutexes = ["pi", "glibc", "hinted"]
    med = {c: [statistics.median(by(rows, "E5", f"{m}_blocked_mean_ms").get(c, [float("nan")]))
               for m in mutexes] for c in ("B5", "B6")}
    if all(v != v for vals in med.values() for v in vals):  # all NaN
        return False
    fig, ax = plt.subplots(figsize=(6, 4.5))
    w = 0.38
    for i, c in enumerate(("B5", "B6")):
        ax.bar([x + (i - 0.5) * w for x in range(len(mutexes))], med[c], w, label=LABELS[c])
    ax.set_xticks(range(len(mutexes)), ["PI futex", "glibc mutex", "hinted"])
    ax.set_yscale("log")
    ax.set_ylabel("mean time blocked per acquisition (ms, log)")
    ax.set_title("E5: priority inversion, holder at background class")
    ax.legend()
    ax.grid(alpha=0.3, axis="y")
    fig.tight_layout()
    fig.savefig(out / "fig4_e5_inversion.png", dpi=150)
    return True


def fig5(rows, resdir, out):
    p99 = by(rows, "E6", "wakeup_p99.0_us", key="x_guard")
    wait = by(rows, "E6", "bg_wait_max_ms", key="x_guard")
    gs = sorted((g for g in p99 if g), key=float)
    if not gs:
        return False
    fig, ax1 = plt.subplots(figsize=(6, 4.5))
    ax1.plot([float(g) for g in gs], [statistics.median(p99[g]) for g in gs], "o-", label="FG p99 (µs)")
    ax1.set_xlabel("guard interval (ms)")
    ax1.set_ylabel("foreground p99 wakeup latency (µs)")
    ax2 = ax1.twinx()
    ax2.plot([float(g) for g in gs], [statistics.median(wait.get(g, [float("nan")])) for g in gs],
             "s--", color="tab:orange", label="longest BG wait (ms)")
    ax2.set_ylabel("longest background wait (ms)")
    fig.legend(loc="upper center", ncol=2, fontsize=9)
    ax1.set_title("E6: guard interval sweep", pad=24)
    ax1.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out / "fig5_e6_guard_sweep.png", dpi=150)
    return True


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    resdir = Path(argv[1])
    rows = load(resdir)
    out = resdir / "figures"
    out.mkdir(exist_ok=True)
    for f in (fig1, fig2, fig3, fig4, fig5):
        made = f(rows, resdir, out)
        print(f"{f.__name__}: {'written' if made else 'no data, skipped'}")


if __name__ == "__main__":
    main(sys.argv)
