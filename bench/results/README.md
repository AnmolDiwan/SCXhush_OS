# Synthetic results — not measurements

These CSVs are written by `bench/run_experiments.py`, which samples from the
hand-picked distributions in `bench/workloads.py` (for example, B6 latency is
`lognormal(mean=0.32, sigma=0.26)` by construction). The same goes for
`reports/scx_hush_evaluation.html`. They are useful for checking the report
pipeline and the demo, and they say nothing about how scx_hush performs.

Measured results come from `bench/real/run.py` on a kernel with
`CONFIG_SCHED_CLASS_EXT=y` and are written to `bench/real/results/`.
