// SPDX-License-Identifier: GPL-2.0
/*
 * periodic_loop - 100 Hz control-loop stand-in for experiments E2 and E9.
 *
 * Sleeps to absolute deadlines with clock_nanosleep(TIMER_ABSTIME), does a
 * fixed amount of work per cycle, and records how late each wakeup was and
 * how far each period deviated from nominal. The thread is named "ctl_loop"
 * so a policy comm rule can classify it.
 *
 *   periodic_loop --hz 100 --duration 120 --work-us 500 --out jitter.csv
 */
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>

static uint64_t ts_ns(const struct timespec *ts)
{
	return (uint64_t)ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts_ns(&ts);
}

static void spin_ns(uint64_t ns)
{
	uint64_t end = now_ns() + ns;

	while (now_ns() < end)
		;
}

static int cmp_i64(const void *a, const void *b)
{
	int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "hz", required_argument, NULL, 'z' },
		{ "duration", required_argument, NULL, 'd' },
		{ "work-us", required_argument, NULL, 'w' },
		{ "out", required_argument, NULL, 'o' },
		{ "name", required_argument, NULL, 'n' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	double hz = 100, duration = 10;
	uint64_t work_ns = 500000, period, next, prev_wake = 0;
	const char *out = NULL, *name = "ctl_loop";
	int64_t *late, *dev;
	size_t n, i;
	struct timespec ts;
	FILE *f = NULL;
	int opt;

	while ((opt = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (opt) {
		case 'z': hz = atof(optarg); break;
		case 'd': duration = atof(optarg); break;
		case 'w': work_ns = strtoull(optarg, NULL, 10) * 1000; break;
		case 'o': out = optarg; break;
		case 'n': name = optarg; break;
		default:
			fprintf(stderr, "usage: %s [--hz N] [--duration S] [--work-us US] "
				"[--out CSV] [--name COMM]\n", argv[0]);
			return opt == 'h' ? 0 : 2;
		}
	}
	if (hz <= 0 || duration <= 0) {
		fprintf(stderr, "hz and duration must be positive\n");
		return 2;
	}
	prctl(PR_SET_NAME, name);
	period = (uint64_t)(1e9 / hz);
	n = (size_t)(duration * hz);
	late = calloc(n, sizeof(*late));
	dev = calloc(n, sizeof(*dev));
	if (!late || !dev)
		return 1;

	next = now_ns() + period;
	for (i = 0; i < n; i++) {
		uint64_t wake;

		ts.tv_sec = next / 1000000000ULL;
		ts.tv_nsec = next % 1000000000ULL;
		while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR)
			;
		wake = now_ns();
		late[i] = (int64_t)(wake - next);
		dev[i] = prev_wake ? (int64_t)(wake - prev_wake) - (int64_t)period : 0;
		prev_wake = wake;
		spin_ns(work_ns);
		next += period;
	}

	if (out) {
		f = fopen(out, "w");
		if (!f) {
			perror(out);
			return 1;
		}
		fprintf(f, "cycle,wake_late_ns,period_dev_ns\n");
		for (i = 0; i < n; i++)
			fprintf(f, "%zu,%lld,%lld\n", i, (long long)late[i], (long long)dev[i]);
		fclose(f);
	}

	/* Summary on stderr: p50/p99/max of |period deviation| and lateness. */
	for (i = 0; i < n; i++)
		dev[i] = llabs(dev[i]);
	qsort(late, n, sizeof(*late), cmp_i64);
	qsort(dev, n, sizeof(*dev), cmp_i64);
	fprintf(stderr,
		"periodic_loop: %zu cycles @ %.0f Hz; late p50 %.1f us p99 %.1f us max %.1f us; "
		"|period dev| p99 %.1f us max %.1f us\n",
		n, hz, late[n / 2] / 1e3, late[(size_t)(n * 0.99)] / 1e3, late[n - 1] / 1e3,
		dev[(size_t)(n * 0.99)] / 1e3, dev[n - 1] / 1e3);
	free(late);
	free(dev);
	return 0;
}
