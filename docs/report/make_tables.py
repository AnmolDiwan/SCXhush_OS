#!/usr/bin/env python3
"""
Generate the report's result tables from a bench/real/run.py campaign.

    docs/report/make_tables.py <campaign dir>

Writes results_e1.tex, results_e2.tex and results_text.tex next to this
script and copies the campaign's figures into figures/. Every number in the
Results section comes from <campaign>/summary.csv; nothing is typed by hand.
"""

import csv
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMES = {"B0": "FG alone", "B1": "EEVDF", "B2": "nice 19", "B3": "SCHED\\_IDLE",
         "B4": "cpu.idle", "B5": "scx\\_hush (no inv.)", "B6": "scx\\_hush"}


def load(campaign):
    rows = {}
    for r in csv.DictReader(open(campaign / "summary.csv")):
        rows[(r["experiment"], r["config"], r["metric"])] = r
    n_reps = {}
    for r in rows.values():
        n_reps[(r["experiment"], r["config"])] = int(r["n"])
    return rows, n_reps


def cell(rows, exp, cfg, metric, scale=1.0, fmt="{:.1f}"):
    r = rows.get((exp, cfg, metric))
    if not r:
        return "\\pending" if cfg in ("B5", "B6") else "n/a"
    med, lo, hi = (float(r[k]) / scale for k in ("median", "ci_lo", "ci_hi"))
    return f"{fmt.format(med)} {{\\scriptsize[{fmt.format(lo)}, {fmt.format(hi)}]}}"


def median(rows, exp, cfg, metric):
    r = rows.get((exp, cfg, metric))
    return float(r["median"]) if r else None


def table(rows, n_reps, exp, caption, label, cols):
    out = ["\\begin{table}[h]", "\\centering\\small",
           f"\\caption{{{caption} Median over repetitions, 95\\% bootstrap CI in brackets.}}",
           f"\\label{{{label}}}",
           "\\begin{tabular}{@{}l" + "r" * len(cols) + "@{}}", "\\toprule",
           "Config & " + " & ".join(c[0] for c in cols) + " \\\\", "\\midrule"]
    for cfg in NAMES:
        if cfg == "B4" and not any((exp, cfg, c[1]) in rows for c in cols):
            vals = ["n/a"] * len(cols)
        else:
            vals = [cell(rows, exp, cfg, m, s, f) for _, m, s, f in cols]
        out.append(f"{cfg} {NAMES[cfg]} & " + " & ".join(vals) + " \\\\")
    out += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return "\n".join(out) + "\n"


def ratio(rows, exp, metric, cfg):
    a, b = median(rows, exp, cfg, metric), median(rows, exp, "B0", metric)
    return a / b if a is not None and b else None


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    campaign = Path(argv[1])
    rows, n_reps = load(campaign)

    e1 = table(rows, n_reps, "E1", "E1: schbench wakeup latency ($\\mu$s) and background progress.",
               "tab:e1", [("p99 wakeup", "wakeup_p99.0_us", 1, "{:.0f}"),
                          ("p99.9 wakeup", "wakeup_p99.9_us", 1, "{:.0f}"),
                          ("BG CPU-s/min", "bg_cpu_s_per_min", 1, "{:.0f}")])
    e2 = table(rows, n_reps, "E2", "E2: 100\\,Hz control loop, period deviation and wake-up lateness (ms).",
               "tab:e2", [("p99 $|$dev$|$", "period_dev_p99_us", 1000, "{:.2f}"),
                          ("max $|$dev$|$", "period_dev_max_us", 1000, "{:.1f}"),
                          ("p99 late", "wake_late_p99_us", 1000, "{:.2f}"),
                          ("BG CPU-s/min", "bg_cpu_s_per_min", 1, "{:.0f}")])
    (HERE / "results_e1.tex").write_text(e1)
    (HERE / "results_e2.tex").write_text(e2)

    # Narrative: only ratios computed from the medians above.
    parts = []
    r = {c: ratio(rows, "E1", "wakeup_p99.0_us", c) for c in ("B1", "B2", "B3")}
    if all(v is not None for v in r.values()):
        parts.append(
            "With CPU-bound background load at the same priority (B1), the p99 wakeup latency "
            f"of schbench rose to {r['B1']:.1f}$\\times$ the foreground-alone value (B0). "
            f"Background at nice~19 (B2) gave {r['B2']:.1f}$\\times$ and \\code{{SCHED\\_IDLE}} (B3) "
            f"{r['B3']:.1f}$\\times$ (\\cref{{tab:e1}}).")
    r2 = {c: ratio(rows, "E2", "period_dev_p99_us", c) for c in ("B1", "B2", "B3")}
    if all(v is not None for v in r2.values()):
        b0 = median(rows, "E2", "B0", "period_dev_p99_us") / 1000
        b0max = median(rows, "E2", "B0", "period_dev_max_us") / 1000
        if min(r2.values()) < 1.0 or b0 > 1.0:
            # The reference itself is noisy: say so instead of reporting ratios.
            parts.append(
                "E2 is inconclusive on this machine. The 100\\,Hz loop running \\emph{alone} (B0) "
                f"already showed a p99 period deviation of {b0:.1f}\\,ms and a maximum of "
                f"{b0max:.0f}\\,ms (\\cref{{tab:e2}}), i.e.\\ the virtual machine's timer and "
                "vCPU scheduling dominate the jitter, so differences between B1--B3 cannot be "
                "attributed to the background priority mechanism. E2 must be repeated on bare metal.")
        else:
            parts.append(
                "For the 100\\,Hz loop (\\cref{tab:e2}), the p99 period deviation relative to B0 was "
                f"{r2['B1']:.1f}$\\times$ (B1), {r2['B2']:.1f}$\\times$ (B2) and {r2['B3']:.1f}$\\times$ (B3).")
    bg = {c: median(rows, "E1", c, "bg_cpu_s_per_min") for c in ("B1", "B2", "B3")}
    if all(v is not None for v in bg.values()):
        parts.append(
            "Background progress was similar across B1--B3 "
            f"({min(bg.values()):.0f}--{max(bg.values()):.0f} CPU-seconds per minute in E1 on "
            "4 vCPUs). The question scx\\_hush targets is whether strict precedence can bring "
            "foreground latency back to B0 at a similar background cost.")
    parts.append(
        "These measurements quantify the interference that motivates scx\\_hush on this machine; "
        "they are not an evaluation of scx\\_hush, and the VM's noise (\\cref{sec:discussion}) "
        "means only large effects should be read from them.")
    (HERE / "results_text.tex").write_text("\\paragraph{Observations.}\n" + "\n".join(parts) + "\n")

    figs = HERE / "figures"
    figs.mkdir(exist_ok=True)
    for f in (campaign / "figures").glob("*.png"):
        shutil.copy(f, figs / f.name)
    print("wrote results_e1.tex, results_e2.tex, results_text.tex; figures:",
          sorted(p.name for p in figs.glob("*.png")))


if __name__ == "__main__":
    main(sys.argv)
