# scx_hush technical report

`scx_hush_report.tex` (+ `refs.bib`) → `scx_hush_report.pdf`.

The Results tables, narrative and figures are generated from a
`bench/real/run.py` campaign, so no number is typed by hand:

```sh
sudo bench/real/run.py -e E1,E2 --reps 3 --duration 20 --warmup 5 --out /tmp/campaign
bench/real/plot.py /tmp/campaign
docs/report/make_tables.py /tmp/campaign
cd docs/report && latexmk -pdf scx_hush_report.tex
```

The committed tables come from the campaign recorded in
`campaign_meta.json` / `campaign_summary.csv` (4-vCPU VM, kernel without
sched_ext, so B4–B6 were skipped). Rerun on a sched_ext kernel to fill in the
scx_hush rows.
