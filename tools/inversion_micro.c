// SPDX-License-Identifier: GPL-2.0
/*
 * inversion_micro - priority-inversion micro-benchmark for experiment E5.
 *
 * Thread "inv_fg" (FOREGROUND) repeatedly takes mutex M and records how long
 * each acquisition blocked. Thread "inv_bg" (BACKGROUND) holds M for
 * --hold-ms of CPU work at a time. --load threads named "inv_load"
 * (FOREGROUND) keep every other CPU busy, so without inversion handling the
 * holder only runs when the starvation guard fires.
 *
 *   --mutex pi      PTHREAD_PRIO_INHERIT mutex (tier 2)
 *   --mutex glibc   default glibc mutex (tier 3)
 *   --mutex hinted  default mutex plus hush_critical_enter/exit (tier 1)
 *
 * Classes come from comm rules in bench/real/policy.bench.toml.
 */
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libhush.h"

enum mode { M_PI, M_GLIBC, M_HINTED };

static pthread_mutex_t lock;
static enum mode mode;
static uint64_t hold_ns = 5000000, deadline;
static volatile bool stop;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void spin_ns(uint64_t ns)
{
	uint64_t end = now_ns() + ns;

	while (now_ns() < end && !stop)
		;
}

static void *bg_holder(void *arg)
{
	pthread_setname_np(pthread_self(), "inv_bg");
	while (!stop) {
		pthread_mutex_lock(&lock);
		if (mode == M_HINTED)
			hush_critical_enter();
		spin_ns(hold_ns);
		if (mode == M_HINTED)
			hush_critical_exit();
		pthread_mutex_unlock(&lock);
		/* Let the waiter in; a holder that never sleeps is a spinlock test. */
		usleep(1000);
	}
	return NULL;
}

static void *fg_load(void *arg)
{
	volatile uint64_t x = 0;

	pthread_setname_np(pthread_self(), "inv_load");
	while (!stop)
		x++;
	return NULL;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "mutex", required_argument, NULL, 'm' },
		{ "duration", required_argument, NULL, 'd' },
		{ "hold-ms", required_argument, NULL, 'H' },
		{ "load", required_argument, NULL, 'l' },
		{ "out", required_argument, NULL, 'o' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	const char *out = NULL, *mname = "glibc";
	double duration = 10;
	long nload = sysconf(_SC_NPROCESSORS_ONLN) - 1;
	pthread_mutexattr_t attr;
	pthread_t bg, *load;
	uint64_t *blocked = NULL, sum = 0;
	size_t n = 0, cap = 0;
	FILE *f = NULL;
	int opt;

	while ((opt = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
		switch (opt) {
		case 'm': mname = optarg; break;
		case 'd': duration = atof(optarg); break;
		case 'H': hold_ns = (uint64_t)(atof(optarg) * 1e6); break;
		case 'l': nload = atol(optarg); break;
		case 'o': out = optarg; break;
		default:
			fprintf(stderr, "usage: %s --mutex pi|glibc|hinted [--duration S] "
				"[--hold-ms MS] [--load N] [--out CSV]\n", argv[0]);
			return opt == 'h' ? 0 : 2;
		}
	}
	if (!strcmp(mname, "pi"))
		mode = M_PI;
	else if (!strcmp(mname, "glibc"))
		mode = M_GLIBC;
	else if (!strcmp(mname, "hinted"))
		mode = M_HINTED;
	else {
		fprintf(stderr, "unknown --mutex %s\n", mname);
		return 2;
	}
	if (nload < 0)
		nload = 0;

	pthread_mutexattr_init(&attr);
	if (mode == M_PI && pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT)) {
		fprintf(stderr, "PTHREAD_PRIO_INHERIT unsupported\n");
		return 1;
	}
	pthread_mutex_init(&lock, &attr);
	pthread_setname_np(pthread_self(), "inv_fg");

	load = calloc(nload ? nload : 1, sizeof(*load));
	pthread_create(&bg, NULL, bg_holder, NULL);
	for (long i = 0; i < nload; i++)
		pthread_create(&load[i], NULL, fg_load, NULL);

	usleep(100000);	/* let the holder grab the lock first */
	deadline = now_ns() + (uint64_t)(duration * 1e9);
	while (now_ns() < deadline) {
		uint64_t t0, t1;

		t0 = now_ns();
		pthread_mutex_lock(&lock);
		t1 = now_ns();
		pthread_mutex_unlock(&lock);
		if (n == cap) {
			cap = cap ? cap * 2 : 4096;
			blocked = realloc(blocked, cap * sizeof(*blocked));
			if (!blocked)
				return 1;
		}
		blocked[n++] = t1 - t0;
		usleep(2000);
	}
	stop = true;
	pthread_join(bg, NULL);
	for (long i = 0; i < nload; i++)
		pthread_join(load[i], NULL);

	if (out && (f = fopen(out, "w"))) {
		fprintf(f, "mutex,acquisition,blocked_ns\n");
		for (size_t i = 0; i < n; i++)
			fprintf(f, "%s,%zu,%llu\n", mname, i, (unsigned long long)blocked[i]);
		fclose(f);
	}
	for (size_t i = 0; i < n; i++)
		sum += blocked[i];
	qsort(blocked, n, sizeof(*blocked), cmp_u64);
	if (n)
		fprintf(stderr,
			"inversion_micro[%s]: %zu acquisitions; blocked mean %.2f ms p50 %.2f ms "
			"p99 %.2f ms max %.2f ms\n",
			mname, n, sum / 1e6 / n, blocked[n / 2] / 1e6,
			blocked[(size_t)(n * 0.99)] / 1e6, blocked[n - 1] / 1e6);
	free(blocked);
	free(load);
	return 0;
}
