// SPDX-License-Identifier: GPL-2.0
/*
 * hushd - load scx_hush, keep its policy maps current, serve hushctl.
 *
 *   sudo hushd --policy policy.toml        (NFR-11; Ctrl-C unloads, FR-20)
 *   hushd --dry-run --policy policy.toml   validate and show the resolution
 *   hushd --selftest                       kernel and glibc checks
 */
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>

#include "hush.skel.h"
#include "hushd.h"
#include "util.h"

static struct hushd D = {
	.listen_fd = -1,
	.inotify_fd = -1,
	.epfd = -1,
};

static uint64_t loaded_watchdog_ms;

/* ------------------------------------------------------------ maps */

static int map_fd(struct hushd *d, enum hush_map m)
{
	if (!d->skel)
		return -1;
	switch (m) {
	case MAP_CGROUP:
		return bpf_map__fd(d->skel->maps.class_by_cgroup);
	case MAP_COMM:
		return bpf_map__fd(d->skel->maps.class_by_comm);
	case MAP_UID:
		return bpf_map__fd(d->skel->maps.class_by_uid);
	case MAP_PID:
		return bpf_map__fd(d->skel->maps.class_by_pid);
	case MAP_CONFIG:
		return bpf_map__fd(d->skel->maps.hush_cfg);
	}
	return -1;
}

int hushd_map_update(struct hushd *d, enum hush_map m, const void *key, const void *val)
{
	int fd = map_fd(d, m);

	/* --dry-run and --no-load have no maps; the policy logic still runs. */
	if (!d->skel)
		return 0;
	if (fd < 0)
		return -EBADF;
	if (bpf_map_update_elem(fd, key, val, BPF_ANY)) {
		int err = -errno;

		log_warn("map update (map %d): %s", m, strerror(errno));
		return err;
	}
	return 0;
}

int hushd_map_delete(struct hushd *d, enum hush_map m, const void *key)
{
	int fd = map_fd(d, m);

	if (!d->skel)
		return 0;
	if (fd < 0)
		return -EBADF;
	return bpf_map_delete_elem(fd, key) && errno != ENOENT ? -errno : 0;
}

int hushd_push_config(struct hushd *d)
{
	uint32_t zero = 0;

	return hushd_map_update(d, MAP_CONFIG, &zero, &d->cfg);
}

static void bump_generation(struct hushd *d)
{
	/* 0 is reserved: the exec hook zeroes a task's gen to force re-classification. */
	if (++d->cfg.policy_gen == 0)
		d->cfg.policy_gen = 1;
	hushd_push_config(d);
}

/* Delete every key of @m for which @keep returns false. */
static void map_prune(struct hushd *d, enum hush_map m, size_t key_sz,
		      bool (*keep)(struct hushd *, const void *))
{
	char key[HUSH_COMM_LEN], next[HUSH_COMM_LEN];
	int fd = map_fd(d, m);
	void *cur = NULL;

	if (fd < 0 || key_sz > sizeof(key))
		return;
	while (!bpf_map_get_next_key(fd, cur, next)) {
		memcpy(key, next, key_sz);
		cur = key;
		if (!keep(d, key)) {
			bpf_map_delete_elem(fd, key);
			cur = NULL;	/* restart: iteration order changed */
		}
	}
}

static bool keep_comm(struct hushd *d, const void *key)
{
	char comm[HUSH_COMM_LEN + 1] = {};

	memcpy(comm, key, HUSH_COMM_LEN);
	return policy_comm_class(&d->pol, comm, NULL) != 0;
}

static bool keep_uid(struct hushd *d, const void *key)
{
	return policy_uid_class(&d->pol, *(const uint32_t *)key, NULL) != 0;
}

/* Write class_by_comm and class_by_uid from the rule list (first match wins). */
static void push_rule_maps(struct hushd *d)
{
	for (int i = 0; i < d->pol.nr_rules; i++) {
		const struct hush_rule *r = &d->pol.rules[i];

		for (int j = 0; j < r->nr; j++) {
			int rule;
			uint8_t cls;

			if (r->kind == RULE_COMM) {
				char key[HUSH_COMM_LEN] = {};

				/* An earlier rule already claimed this comm. */
				if (policy_comm_class(&d->pol, r->pats[j], &rule) && rule != i)
					continue;
				strncpy(key, r->pats[j], sizeof(key) - 1);
				cls = r->cls;
				if (d->dry_run)
					printf("  comm   %-16s -> %s\n", r->pats[j], class_name(cls));
				hushd_map_update(d, MAP_COMM, key, &cls);
			} else if (r->kind == RULE_UID) {
				uint32_t uid = r->uids[j];

				if (policy_uid_class(&d->pol, uid, &rule) && rule != i)
					continue;
				cls = r->cls;
				if (d->dry_run)
					printf("  uid    %-16u -> %s\n", uid, class_name(cls));
				hushd_map_update(d, MAP_UID, &uid, &cls);
			}
		}
	}
	if (d->skel) {
		map_prune(d, MAP_COMM, HUSH_COMM_LEN, keep_comm);
		map_prune(d, MAP_UID, sizeof(uint32_t), keep_uid);
	}
}

static void build_config(struct hushd *d)
{
	policy_to_config(&d->pol, &d->cfg);
	if (d->no_inversion)
		d->cfg.flags &= ~(HUSH_F_INVERSION | HUSH_F_FALLBACK | HUSH_F_HINTS);
	if (d->tier3_ok && (d->cfg.flags & HUSH_F_INVERSION))
		d->cfg.flags |= HUSH_F_TIER3;
	if (d->trace)
		d->cfg.flags |= HUSH_F_TRACE;
}

/* ------------------------------------------------------------ stats */

static int read_stats(struct hushd *d, struct hush_stats *sum)
{
	struct hush_stats *v;
	uint32_t zero = 0;
	int fd;

	memset(sum, 0, sizeof(*sum));
	if (!d->skel)
		return -ENODEV;
	fd = bpf_map__fd(d->skel->maps.stats);
	v = calloc(d->nr_cpus, sizeof(*v));
	if (!v)
		return -ENOMEM;
	if (bpf_map_lookup_elem(fd, &zero, v)) {
		free(v);
		return -errno;
	}
	for (int c = 0; c < d->nr_cpus; c++) {
		uint64_t *dst = (uint64_t *)sum, *src = (uint64_t *)&v[c];

		for (size_t i = 0; i < sizeof(*sum) / sizeof(uint64_t); i++)
			dst[i] += src[i];
		for (int k = 0; k < HUSH_NR_CLASSES; k++) {
			/* max, not sum, for the longest single wait */
			sum->wait_max_ns[k] -= v[c].wait_max_ns[k];
			if (v[c].wait_max_ns[k] > sum->wait_max_ns[k])
				sum->wait_max_ns[k] = v[c].wait_max_ns[k];
		}
	}
	free(v);
	return 0;
}

/* ------------------------------------------------------------ tracing */

static int trace_event_cb(void *ctx, void *data, size_t len)
{
	struct hushd *d = ctx;
	const struct hush_trace_event *ev = data;
	char comm[HUSH_COMM_LEN + 1] = {};

	if (!d->trace || len < sizeof(*ev))
		return 0;
	memcpy(comm, ev->comm, HUSH_COMM_LEN);
	for (char *c = comm; *c; c++)
		if (*c == ',' || *c == '"' || !isprint((unsigned char)*c))
			*c = '_';
	fprintf(d->trace, "%llu,%u,%u,%s,%s,%llu,%u\n", (unsigned long long)ev->ts_ns, ev->pid,
		ev->tid, comm, class_name(ev->cls), (unsigned long long)ev->wait_ns, ev->cpu);
	d->trace_events++;
	return 0;
}

static int trace_start(struct hushd *d, const char *path, char *msg, size_t len)
{
	if (d->trace) {
		sfmt(msg, len, "already tracing to %s", d->trace_path);
		return -EBUSY;
	}
	if (path[0] != '/') {
		sfmt(msg, len, "trace path must be absolute");
		return -EINVAL;
	}
	d->trace = fopen(path, "we");
	if (!d->trace) {
		sfmt(msg, len, "%s: %s", path, strerror(errno));
		return -errno;
	}
	sfmt(d->trace_path, sizeof(d->trace_path), "%s", path);
	fprintf(d->trace, "timestamp_ns,pid,tid,comm,class,wait_ns,cpu\n");
	d->trace_events = 0;
	d->cfg.flags |= HUSH_F_TRACE;
	hushd_push_config(d);
	sfmt(msg, len, "tracing wakeup latency to %s", path);
	return 0;
}

static int trace_stop(struct hushd *d, char *msg, size_t len)
{
	if (!d->trace) {
		sfmt(msg, len, "not tracing");
		return -EINVAL;
	}
	d->cfg.flags &= ~HUSH_F_TRACE;
	hushd_push_config(d);
	if (d->rb)
		ring_buffer__consume(d->rb);
	fclose(d->trace);
	d->trace = NULL;
	sfmt(msg, len, "wrote %llu events to %s", (unsigned long long)d->trace_events,
	     d->trace_path);
	return 0;
}

/* ------------------------------------------------------------ commands */

static void reply_error(struct jw *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void reply_error(struct jw *w, const char *fmt, ...)
{
	char msg[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	jw_str(w, "status", "error");
	jw_str(w, "message", msg);
}

static void reply_ok(struct jw *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void reply_ok(struct jw *w, const char *fmt, ...)
{
	char msg[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	jw_str(w, "status", "ok");
	jw_str(w, "message", msg);
}

static void cmd_status(struct hushd *d, struct jw *w)
{
	static const char *const cls_key[] = { NULL, "FOREGROUND", "NORMAL", "BACKGROUND" };
	struct hush_stats s;
	char state[64] = "unknown", ops[64] = "";

	read_text("/sys/kernel/sched_ext/state", state, sizeof(state));
	read_text("/sys/kernel/sched_ext/root/ops", ops, sizeof(ops));
	read_stats(d, &s);

	jw_str(w, "status", "ok");
	jw_str(w, "backend", d->skel ? "bpf" : "no-load");
	jw_str(w, "version", HUSHD_VERSION);
	jw_u64(w, "policy_gen", d->cfg.policy_gen);
	jw_str(w, "policy", d->policy_path);
	jw_str(w, "sched_ext_state", state);
	jw_str(w, "ops", ops);
	jw_u64(w, "uptime_s", (mono_ns() - d->start_ns) / 1000000000ULL);
	jw_u64(w, "cgroups_classified", d->nr_cg_mapped);
	jw_u64(w, "pid_overrides", d->nr_pid_ov);
	jw_u64(w, "cgroup_overrides", d->nr_cg_ov);

	jw_obj_begin(w, "classes");
	for (int k = HUSH_CLASS_FG; k < HUSH_NR_CLASSES; k++) {
		jw_obj_begin(w, cls_key[k]);
		jw_u64(w, "runtime_ns", s.runtime_ns[k]);
		jw_u64(w, "wait_ns", s.wait_ns[k]);
		jw_u64(w, "wait_max_ns", s.wait_max_ns[k]);
		jw_u64(w, "runs", s.nr_runs[k]);
		jw_obj_end(w);
	}
	jw_obj_end(w);

	jw_obj_begin(w, "counters");
	jw_u64(w, "preempt_kicks", s.preempt_kicks);
	jw_u64(w, "tick_yields", s.tick_yields);
	jw_u64(w, "guard_firings", s.guard_firings);
	jw_u64(w, "guard_normal", s.guard_normal);
	jw_u64(w, "hard_guard_firings", s.hard_guard_firings);
	jw_u64(w, "boosts_hint", s.boosts[HUSH_BOOST_HINT]);
	jw_u64(w, "boosts_pi", s.boosts[HUSH_BOOST_PI]);
	jw_u64(w, "boosts_glibc", s.boosts[HUSH_BOOST_GLIBC]);
	jw_u64(w, "boosts_fallback", s.boosts[HUSH_BOOST_FALLBACK]);
	jw_u64(w, "boost_renewals", s.boost_renewals);
	jw_u64(w, "boost_promotions", s.boost_promotions);
	jw_u64(w, "boost_capped", s.boost_capped);
	jw_u64(w, "hint_abuse", s.hint_abuse);
	jw_u64(w, "dstate_escapes", s.dstate_escapes);
	jw_u64(w, "reclassify", s.reclassify);
	jw_obj_end(w);

	jw_obj_begin(w, "features");
	jw_bool(w, "inversion", d->cfg.flags & HUSH_F_INVERSION);
	jw_bool(w, "tier3", d->cfg.flags & HUSH_F_TIER3);
	jw_bool(w, "fallback", d->cfg.flags & HUSH_F_FALLBACK);
	jw_bool(w, "dstate", d->cfg.flags & HUSH_F_DSTATE);
	jw_bool(w, "hints", (d->cfg.flags & HUSH_F_HINTS) && d->hint_links[0]);
	jw_bool(w, "trace", d->trace != NULL);
	jw_obj_end(w);

	jw_obj_begin(w, "config");
	jw_u64(w, "fg_slice_ms", d->pol.p.fg_slice_ms);
	jw_u64(w, "normal_slice_ms", d->pol.p.normal_slice_ms);
	jw_u64(w, "bg_slice_ms", d->pol.p.bg_slice_ms);
	jw_u64(w, "guard_ms", d->pol.p.guard_ms);
	jw_u64(w, "boost_ms", d->pol.p.boost_ms);
	jw_u64(w, "boost_cap_pct", d->pol.p.boost_cap_pct);
	jw_u64(w, "watchdog_ms", loaded_watchdog_ms ? loaded_watchdog_ms : d->pol.p.watchdog_ms);
	jw_obj_end(w);
}

static int proc_status_field(int pid, const char *field, long *out)
{
	char path[64], line[256];
	size_t n = strlen(field);
	FILE *f;

	sfmt(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "re");
	if (!f)
		return -errno;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, field, n) && line[n] == ':') {
			*out = strtol(line + n + 1, NULL, 10);
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -ENOENT;
}

/* Mirror of effective_class() in scx_hush.bpf.c, for reporting only. */
static int effective_class_user(const struct task_ctx *t, const struct hush_config *cfg,
				uint64_t now, const char **why)
{
	int base = t->base_class ? t->base_class : HUSH_CLASS_NORMAL;
	uint64_t cap = HUSH_BOOST_WINDOW_NS / 100 *
		       (cfg->boost_cap_pct ? cfg->boost_cap_pct : HUSH_DFL_BOOST_CAP_PCT);
	bool allowed = now - t->boost_win_start >= HUSH_BOOST_WINDOW_NS || t->boost_used_ns < cap;
	static const char *const src[] = { "hint", "PI futex", "glibc mutex", "same-process fallback" };

	*why = NULL;
	if (base != HUSH_CLASS_FG && allowed) {
		if (t->boost_until > now) {
			*why = src[t->boost_src & 3];
			return HUSH_CLASS_FG;
		}
		if (t->crit_depth && (cfg->flags & HUSH_F_HINTS)) {
			*why = "hint";
			return HUSH_CLASS_FG;
		}
	}
	return base;
}

static void cmd_class(struct hushd *d, const struct json_obj *args, struct jw *w)
{
	static const char *const reasons[] = {
		"no rule matched (default)", "hushctl promote/demote", "cgroup rule", "comm rule",
		"uid rule", "inherited from parent at fork", "kernel thread",
	};
	char comm[32] = "", cg[PATH_MAX] = "", path[64], desc[512] = "";
	long tgid = 0, uid = -1;
	int64_t pid;
	int cls = 0, rule = -1;
	const char *src = "default";

	if (!json_get_i64(args, "pid", &pid) || pid <= 0) {
		reply_error(w, "class: need a numeric pid");
		return;
	}
	sfmt(path, sizeof(path), "/proc/%lld/comm", (long long)pid);
	if (read_text(path, comm, sizeof(comm)) < 0) {
		reply_error(w, "pid %lld: no such process", (long long)pid);
		return;
	}
	proc_status_field(pid, "Tgid", &tgid);
	proc_status_field(pid, "Uid", &uid);
	cg_path_of_pid(pid, cg, sizeof(cg));

	/* Explain the policy decision the same way the BPF side makes it. */
	for (int i = 0; i < d->nr_pid_ov; i++) {
		if (d->pid_ov[i].tgid == tgid) {
			cls = d->pid_ov[i].cls;
			src = "pid override";
			sfmt(desc, sizeof(desc), "hushctl promote/demote %ld", tgid);
		}
	}
	if (!cls && cg[0] && (cls = policy_cgroup_class(&d->pol, d->cg_ov, d->nr_cg_ov, cg, &rule))) {
		src = "cgroup";
		if (rule >= 0)
			policy_rule_desc(&d->pol, rule, desc, sizeof(desc));
		else
			sfmt(desc, sizeof(desc), "hushctl promote/demote of a cgroup");
	}
	if (!cls && (cls = policy_comm_class(&d->pol, comm, &rule))) {
		src = "comm";
		policy_rule_desc(&d->pol, rule, desc, sizeof(desc));
	}
	if (!cls && uid >= 0 && (cls = policy_uid_class(&d->pol, (uint32_t)uid, &rule))) {
		src = "uid";
		policy_rule_desc(&d->pol, rule, desc, sizeof(desc));
	}

	jw_str(w, "status", "ok");
	jw_i64(w, "pid", pid);
	jw_i64(w, "tgid", tgid);
	jw_str(w, "comm", comm);
	jw_str(w, "cgroup", cg);
	jw_i64(w, "uid", uid);
	jw_str(w, "policy_class", class_name(cls ? cls : HUSH_CLASS_NORMAL));
	jw_str(w, "policy_match", src);
	jw_str(w, "rule", desc[0] ? desc : "no rule matched");

	/* Kernel state through the task-storage map, keyed by pidfd. */
	if (d->skel) {
		struct task_ctx t;
		int pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
		const char *why;
		uint64_t now = mono_ns();
		int eff;

		if (pidfd >= 0 &&
		    !bpf_map_lookup_elem(bpf_map__fd(d->skel->maps.task_ctx), &pidfd, &t)) {
			eff = effective_class_user(&t, &d->cfg, now, &why);
			jw_str(w, "base_class", class_name(t.base_class));
			jw_str(w, "effective_class", class_name(eff));
			jw_str(w, "reason", why ? "boosted" :
				 reasons[t.reason < 7 ? t.reason : 0]);
			if (why)
				jw_str(w, "boost_source", why);
			jw_u64(w, "boost_remaining_us",
			       t.boost_until > now ? (t.boost_until - now) / 1000 : 0);
			jw_u64(w, "crit_depth", t.crit_depth);
			jw_u64(w, "boost_used_us", t.boost_used_ns / 1000);
		} else {
			jw_str(w, "effective_class", class_name(cls ? cls : HUSH_CLASS_NORMAL));
			jw_str(w, "reason", "task not yet seen by the scheduler");
		}
		if (pidfd >= 0)
			close(pidfd);
	} else {
		jw_str(w, "effective_class", class_name(cls ? cls : HUSH_CLASS_NORMAL));
		jw_str(w, "reason", "scheduler not loaded (--no-load)");
	}
}

static bool all_digits(const char *s)
{
	if (!*s)
		return false;
	for (; *s; s++)
		if (!isdigit((unsigned char)*s))
			return false;
	return true;
}

/* promote / demote / reset of a PID (whole process) or a cgroup subtree. */
static void cmd_set_class(struct hushd *d, const struct json_obj *args, int cls, struct jw *w)
{
	const char *target = json_get_str(args, "target");
	const char *verb = cls == HUSH_CLASS_FG ? "promoted to FOREGROUND" :
			   cls == HUSH_CLASS_BG ? "demoted to BACKGROUND" : "reset to policy";

	if (!target || !*target) {
		reply_error(w, "need a target: <pid> or <cgroup path>");
		return;
	}

	if (all_digits(target)) {
		long tgid = 0;
		int pid = atoi(target), i;
		uint32_t key;

		if (proc_status_field(pid, "Tgid", &tgid) || tgid <= 0) {
			reply_error(w, "pid %d: no such process", pid);
			return;
		}
		key = (uint32_t)tgid;
		for (i = 0; i < d->nr_pid_ov && d->pid_ov[i].tgid != key; i++)
			;
		if (cls) {
			uint8_t v = cls;

			if (i == d->nr_pid_ov) {
				struct pid_override *n;

				if (d->nr_pid_ov >= HUSH_MAP_PID_MAX) {
					reply_error(w, "too many pid overrides (max %d)", HUSH_MAP_PID_MAX);
					return;
				}
				n = realloc(d->pid_ov, (d->nr_pid_ov + 1) * sizeof(*n));
				if (!n) {
					reply_error(w, "out of memory");
					return;
				}
				d->pid_ov = n;
				d->nr_pid_ov++;
			}
			d->pid_ov[i].tgid = key;
			d->pid_ov[i].cls = cls;
			hushd_map_update(d, MAP_PID, &key, &v);
		} else if (i < d->nr_pid_ov) {
			d->pid_ov[i] = d->pid_ov[--d->nr_pid_ov];
			hushd_map_delete(d, MAP_PID, &key);
		}
		bump_generation(d);
		reply_ok(w, "process %u %s", key, verb);
		return;
	}

	if (target[0] != '/') {
		reply_error(w, "cgroup path must start with '/' (relative to %s)", d->cg_root);
		return;
	}
	{
		char abs[PATH_MAX + 64];
		struct stat st;
		int i;

		sfmt(abs, sizeof(abs), "%s%s", d->cg_root, target);
		if (stat(abs, &st) || !S_ISDIR(st.st_mode)) {
			reply_error(w, "cgroup %s does not exist", target);
			return;
		}
		for (i = 0; i < d->nr_cg_ov && strcmp(d->cg_ov[i].path, target); i++)
			;
		if (i < d->nr_cg_ov) {
			/* Drop the old entry; re-append below so it is the most recent. */
			memmove(&d->cg_ov[i], &d->cg_ov[i + 1], (d->nr_cg_ov - i - 1) * sizeof(*d->cg_ov));
			d->nr_cg_ov--;
		}
		if (cls) {
			struct cg_override *n = realloc(d->cg_ov, (d->nr_cg_ov + 1) * sizeof(*n));

			if (!n) {
				reply_error(w, "out of memory");
				return;
			}
			d->cg_ov = n;
			sfmt(d->cg_ov[d->nr_cg_ov].path, sizeof(d->cg_ov[0].path), "%s", target);
			d->cg_ov[d->nr_cg_ov].cls = cls;
			d->nr_cg_ov++;
		}
		cg_resync(d);
		bump_generation(d);
		reply_ok(w, "cgroup %s %s", target, verb);
	}
}

static int do_reload(struct hushd *d, char *msg, size_t len)
{
	struct hush_policy np;
	uint32_t gen = d->cfg.policy_gen;
	char err[512];
	int ret;

	ret = policy_load(d->policy_path, &np, err, sizeof(err));
	if (!ret && loaded_watchdog_ms && np.p.watchdog_ms != loaded_watchdog_ms) {
		/* The watchdog is fixed at load; validate against what is running. */
		np.p.watchdog_ms = loaded_watchdog_ms;
		ret = policy_validate(&np.p, err, sizeof(err));
		if (ret)
			policy_free(&np);
		else
			log_warn("watchdog_ms changes need a restart; keeping %llu ms",
				 (unsigned long long)loaded_watchdog_ms);
	}
	if (ret) {
		sfmt(msg, len, "reload rejected, keeping the current policy: %s", err);
		log_err("%s", msg);
		return ret;
	}

	policy_free(&d->pol);
	d->pol = np;
	build_config(d);
	d->cfg.policy_gen = gen;
	push_rule_maps(d);
	cg_resync(d);
	bump_generation(d);
	sfmt(msg, len, "policy reloaded from %s (%d rules, generation %u)", d->policy_path,
	     d->pol.nr_rules, d->cfg.policy_gen);
	log_info("%s", msg);
	return 0;
}

static void cmd_selftest(struct hushd *d, struct jw *w)
{
	struct selftest_check c[SELFTEST_MAX];
	int n = selftest_run(d, c, SELFTEST_MAX), failed = 0;

	jw_str(w, "status", "ok");
	jw_arr_begin(w, "checks");
	for (int i = 0; i < n; i++) {
		jw_obj_begin(w, NULL);
		jw_str(w, "name", c[i].name);
		jw_bool(w, "ok", c[i].ok);
		jw_bool(w, "fatal", c[i].fatal);
		jw_str(w, "detail", c[i].detail);
		jw_obj_end(w);
		failed += !c[i].ok;
	}
	jw_arr_end(w);
	jw_bool(w, "tier3_enabled", d->cfg.flags & HUSH_F_TIER3);
	jw_str(w, "verdict", failed ? "some checks failed; see details" : "all checks passed");
}

void hushd_handle(struct hushd *d, const struct json_obj *req, bool privileged, struct jw *w)
{
	const char *cmd = json_get_str(req, "cmd");
	const struct json_obj *args = json_get_obj(req, "args");
	char msg[600];

	jw_obj_begin(w, NULL);
	if (!cmd) {
		reply_error(w, "missing \"cmd\"");
		goto out;
	}
	if (!strcmp(cmd, "status")) {
		cmd_status(d, w);
		goto out;
	}
	if (!strcmp(cmd, "class")) {
		cmd_class(d, args, w);
		goto out;
	}
	if (!privileged && strcmp(cmd, "ping")) {
		reply_error(w, "'%s' changes scheduler state and needs root", cmd);
		goto out;
	}
	if (!strcmp(cmd, "ping")) {
		reply_ok(w, "pong");
	} else if (!strcmp(cmd, "promote")) {
		cmd_set_class(d, args, HUSH_CLASS_FG, w);
	} else if (!strcmp(cmd, "demote")) {
		cmd_set_class(d, args, HUSH_CLASS_BG, w);
	} else if (!strcmp(cmd, "reset")) {
		cmd_set_class(d, args, 0, w);
	} else if (!strcmp(cmd, "reload")) {
		if (do_reload(d, msg, sizeof(msg)))
			reply_error(w, "%s", msg);
		else {
			reply_ok(w, "%s", msg);
			jw_u64(w, "policy_gen", d->cfg.policy_gen);
		}
	} else if (!strcmp(cmd, "selftest")) {
		cmd_selftest(d, w);
	} else if (!strcmp(cmd, "trace")) {
		const char *action = json_get_str(args, "action");
		const char *file = json_get_str(args, "file");
		int ret;

		if (action && !strcmp(action, "start"))
			ret = trace_start(d, file ? file : "", msg, sizeof(msg));
		else if (action && !strcmp(action, "stop"))
			ret = trace_stop(d, msg, sizeof(msg));
		else {
			ret = -EINVAL;
			sfmt(msg, sizeof(msg), "trace: action must be start or stop");
		}
		if (ret)
			reply_error(w, "%s", msg);
		else
			reply_ok(w, "%s", msg);
	} else {
		reply_error(w, "unknown command '%s'", cmd);
	}
out:
	jw_obj_end(w);
}

/* ------------------------------------------------------------ BPF */

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	/* Warnings include the verifier log on a failed load (§11). */
	if (level == LIBBPF_DEBUG && hush_verbosity < LOG_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static bool kernel_has_sched_ext(void)
{
	struct btf *btf = btf__load_vmlinux_btf();
	bool ok = btf && btf__find_by_name_kind(btf, "sched_ext_ops", BTF_KIND_STRUCT) > 0;

	btf__free(btf);
	return ok;
}

static struct bpf_link *attach_hint(struct hushd *d, struct bpf_program *prog, const char *func)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = func);
	struct bpf_link *l;

	l = bpf_program__attach_uprobe_opts(prog, -1, d->pol.p.libhush_path, 0, &opts);
	if (!l)
		log_warn("uprobe %s:%s: %s", d->pol.p.libhush_path, func, strerror(errno));
	return l;
}

static int load_and_attach(struct hushd *d)
{
	struct scx_hush *skel;
	uint32_t zero = 0;

	if (!kernel_has_sched_ext()) {
		log_err("this kernel has no sched_ext (CONFIG_SCHED_CLASS_EXT); "
			"run 'hushd --selftest' for details");
		return -EOPNOTSUPP;
	}

	skel = SCX_OPS_OPEN(hush_ops, scx_hush);
	d->skel = skel;
	d->nr_cpus = libbpf_num_possible_cpus();
	skel->rodata->nr_cpus = d->nr_cpus;
	skel->struct_ops.hush_ops->timeout_ms = (uint32_t)d->pol.p.watchdog_ms;
	loaded_watchdog_ms = d->pol.p.watchdog_ms;

	if (d->no_inversion)
		bpf_program__set_autoload(skel->progs.hush_sys_enter, false);

	SCX_OPS_LOAD(skel, hush_ops, scx_hush, uei);

	/* Maps before attach, so init_task classifies every task correctly. */
	bpf_map_update_elem(bpf_map__fd(skel->maps.hush_cfg), &zero, &d->cfg, BPF_ANY);
	push_rule_maps(d);
	cg_init(d);
	for (int i = 0; i < d->nr_pid_ov; i++) {
		uint8_t v = d->pid_ov[i].cls;

		hushd_map_update(d, MAP_PID, &d->pid_ov[i].tgid, &v);
	}

	d->ops_link = SCX_OPS_ATTACH(skel, hush_ops, scx_hush);

	if (!d->no_inversion && d->pol.p.hints) {
		if (access(d->pol.p.libhush_path, R_OK) == 0) {
			d->hint_links[0] = attach_hint(d, skel->progs.hush_hint_enter, "hush_critical_enter");
			d->hint_links[1] = attach_hint(d, skel->progs.hush_hint_exit, "hush_critical_exit");
		} else {
			log_warn("%s not found; tier-1 hints disabled", d->pol.p.libhush_path);
		}
	}

	d->rb = ring_buffer__new(bpf_map__fd(skel->maps.trace_rb), trace_event_cb, d, NULL);
	if (!d->rb)
		log_warn("trace ring buffer unavailable: %s", strerror(errno));
	return 0;
}

static void detach(struct hushd *d)
{
	for (int i = 0; i < 2; i++) {
		bpf_link__destroy(d->hint_links[i]);
		d->hint_links[i] = NULL;
	}
	ring_buffer__free(d->rb);
	d->rb = NULL;
	bpf_link__destroy(d->ops_link);
	d->ops_link = NULL;
}

/* ------------------------------------------------------------ main loop */

static void sweep_pid_overrides(struct hushd *d)
{
	for (int i = 0; i < d->nr_pid_ov;) {
		if (kill((pid_t)d->pid_ov[i].tgid, 0) && errno == ESRCH) {
			hushd_map_delete(d, MAP_PID, &d->pid_ov[i].tgid);
			d->pid_ov[i] = d->pid_ov[--d->nr_pid_ov];
			continue;
		}
		i++;
	}
}

static void print_stats_line(struct hushd *d)
{
	struct hush_stats s;

	if (read_stats(d, &s))
		return;
	log_info("fg %.1fs/%.1fms  normal %.1fs/%.1fms  bg %.1fs/%.1fms (runtime/max wait)  "
		 "kicks %llu guard %llu+%llu hard %llu boosts %llu",
		 s.runtime_ns[1] / 1e9, s.wait_max_ns[1] / 1e6,
		 s.runtime_ns[2] / 1e9, s.wait_max_ns[2] / 1e6,
		 s.runtime_ns[3] / 1e9, s.wait_max_ns[3] / 1e6,
		 (unsigned long long)s.preempt_kicks, (unsigned long long)s.guard_firings,
		 (unsigned long long)s.guard_normal, (unsigned long long)s.hard_guard_firings,
		 (unsigned long long)(s.boosts[0] + s.boosts[1] + s.boosts[2] + s.boosts[3]));
}

static int epoll_add(struct hushd *d, int fd)
{
	struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };

	return epoll_ctl(d->epfd, EPOLL_CTL_ADD, fd, &ev);
}

/* Returns the UEI exit code if the kernel unloaded us, 0 on Ctrl-C. */
static int64_t run_loop(struct hushd *d, int sigfd)
{
	struct itimerspec its = { .it_interval = { 1, 0 }, .it_value = { 1, 0 } };
	int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	struct epoll_event evs[16];
	uint64_t ticks = 0;
	int64_t ecode = 0;

	timerfd_settime(tfd, 0, &its, NULL);
	epoll_add(d, tfd);
	epoll_add(d, sigfd);
	if (d->inotify_fd >= 0)
		epoll_add(d, d->inotify_fd);
	if (d->rb)
		epoll_add(d, ring_buffer__epoll_fd(d->rb));

	while (!d->exiting) {
		int n = epoll_wait(d->epfd, evs, 16, -1);

		if (n < 0 && errno == EINTR)
			continue;
		for (int i = 0; i < n; i++) {
			int fd = evs[i].data.fd;

			if (fd == sigfd) {
				struct signalfd_siginfo si;
				char msg[600];

				if (read(sigfd, &si, sizeof(si)) != sizeof(si))
					continue;
				if (si.ssi_signo == SIGHUP)
					do_reload(d, msg, sizeof(msg));
				else
					d->exiting = true;
			} else if (fd == tfd) {
				uint64_t exp;

				if (read(tfd, &exp, sizeof(exp)) < 0)
					continue;
				ticks++;
				if (d->skel && UEI_EXITED(d->skel, uei)) {
					d->exiting = true;
					ecode = -1;
				}
				sweep_pid_overrides(d);
				if (d->stats_interval && ticks % d->stats_interval == 0)
					print_stats_line(d);
			} else if (fd == d->listen_fd) {
				ctl_accept(d);
			} else if (fd == d->inotify_fd) {
				cg_handle_events(d);
			} else if (d->rb && fd == ring_buffer__epoll_fd(d->rb)) {
				ring_buffer__consume(d->rb);
			} else {
				ctl_client_event(d, fd, evs[i].events);
			}
		}
	}
	close(tfd);
	return ecode;
}

static void dry_run(struct hushd *d)
{
	printf("policy %s: OK (%d rules)\n", d->policy_path, d->pol.nr_rules);
	printf("scheduler: fg/normal/bg slice %llu/%llu/%llu ms, guard %llu ms, watchdog %llu ms, "
	       "boost %llu ms (cap %u%%)\n",
	       (unsigned long long)d->pol.p.fg_slice_ms, (unsigned long long)d->pol.p.normal_slice_ms,
	       (unsigned long long)d->pol.p.bg_slice_ms, (unsigned long long)d->pol.p.guard_ms,
	       (unsigned long long)d->pol.p.watchdog_ms, (unsigned long long)d->pol.p.boost_ms,
	       d->pol.p.boost_cap_pct);
	printf("features: inversion=%d tier3=%d (%s) fallback=%d dstate=%d hints=%d\n",
	       !!(d->cfg.flags & HUSH_F_INVERSION), !!(d->cfg.flags & HUSH_F_TIER3), d->tier3_detail,
	       !!(d->cfg.flags & HUSH_F_FALLBACK), !!(d->cfg.flags & HUSH_F_DSTATE),
	       !!(d->cfg.flags & HUSH_F_HINTS));
	printf("comm/uid map entries:\n");
	push_rule_maps(d);
	printf("cgroups (classified only):\n");
	if (!cg_init(d))
		printf("  %d of the cgroups under %s match a rule\n", d->nr_cg_mapped, d->cg_root);
	cg_fini(d);
}

static void usage(FILE *f)
{
	fprintf(f,
		"usage: hushd [options]\n"
		"  -p, --policy FILE     policy file (default %s)\n"
		"  -s, --socket PATH     control socket (default %s)\n"
		"      --no-inversion    B5 ablation: classes and guard only, no inversion handling\n"
		"      --trace FILE      start tracing wakeup latency to FILE immediately\n"
		"      --stats SECONDS   log a counter summary every SECONDS\n"
		"      --dry-run         validate the policy and show what it resolves to\n"
		"      --selftest        check kernel and glibc support, then exit\n"
		"      --cgroup-root DIR cgroup v2 mount to resolve rules against (default: auto)\n"
		"      --no-load         run the control plane without loading BPF (testing)\n"
		"  -v, --verbose         more logging (repeat for libbpf debug)\n"
		"  -V, --version\n"
		"  -h, --help\n"
		"Stop with Ctrl-C; tasks return to the default scheduler. Emergency stop: SysRq-S.\n",
		HUSHD_DFL_POLICY, HUSHD_DFL_SOCK);
}

/* @d is NULL when the policy could not be loaded; policy checks are skipped. */
static int run_selftest_cli(struct hushd *d)
{
	struct selftest_check c[SELFTEST_MAX];
	int n, fatal = 0;

	n = selftest_run(d, c, SELFTEST_MAX);
	for (int i = 0; i < n; i++) {
		printf("  [%s] %-20s %s\n", c[i].ok ? "PASS" : c[i].fatal ? "FAIL" : "WARN", c[i].name,
		       c[i].detail);
		fatal += !c[i].ok && c[i].fatal;
	}
	printf("%s\n", fatal ? "scx_hush cannot run on this machine" :
			       "scx_hush can run on this machine");
	return fatal ? 1 : 0;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "policy", required_argument, NULL, 'p' },
		{ "socket", required_argument, NULL, 's' },
		{ "no-inversion", no_argument, NULL, 'I' },
		{ "trace", required_argument, NULL, 't' },
		{ "stats", required_argument, NULL, 'S' },
		{ "dry-run", no_argument, NULL, 'n' },
		{ "selftest", no_argument, NULL, 'T' },
		{ "cgroup-root", required_argument, NULL, 'C' },
		{ "no-load", no_argument, NULL, 'L' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{}
	};
	const char *trace_file = NULL;
	bool selftest = false, no_load = false;
	char err[600];
	sigset_t mask;
	int opt, sigfd, ret = 0;
	int64_t ecode;

	sfmt(D.policy_path, sizeof(D.policy_path), "%s", HUSHD_DFL_POLICY);
	sfmt(D.sock_path, sizeof(D.sock_path), "%s", HUSHD_DFL_SOCK);

	while ((opt = getopt_long(argc, argv, "p:s:vVh", opts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			sfmt(D.policy_path, sizeof(D.policy_path), "%s", optarg);
			break;
		case 's':
			sfmt(D.sock_path, sizeof(D.sock_path), "%s", optarg);
			break;
		case 'I':
			D.no_inversion = true;
			break;
		case 't':
			trace_file = optarg;
			break;
		case 'S':
			D.stats_interval = atoi(optarg);
			break;
		case 'n':
			D.dry_run = true;
			break;
		case 'T':
			selftest = true;
			break;
		case 'C':
			sfmt(D.cg_root, sizeof(D.cg_root), "%s", optarg);
			break;
		case 'L':
			no_load = true;
			break;
		case 'v':
			hush_verbosity++;
			break;
		case 'V':
			printf("hushd %s\n", HUSHD_VERSION);
			return 0;
		case 'h':
			usage(stdout);
			return 0;
		default:
			usage(stderr);
			return 2;
		}
	}

	if (selftest) {
		if (policy_load(D.policy_path, &D.pol, err, sizeof(err))) {
			log_warn("%s; skipping policy checks", err);
			return run_selftest_cli(NULL);
		}
		ret = run_selftest_cli(&D);
		policy_free(&D.pol);
		return ret;
	}

	if (policy_load(D.policy_path, &D.pol, err, sizeof(err))) {
		log_err("%s", err);
		return 2;
	}
	D.tier3_ok = selftest_glibc_layout(D.tier3_detail, sizeof(D.tier3_detail));
	if (!D.tier3_ok)
		log_warn("tier-3 glibc mutex detection disabled: %s", D.tier3_detail);
	if (D.no_inversion)
		log_info("--no-inversion: priority inversion handling off (B5 ablation)");
	build_config(&D);
	D.cfg.policy_gen = 1;
	D.start_ns = mono_ns();

	if (D.dry_run) {
		dry_run(&D);
		policy_free(&D.pol);
		return 0;
	}

	if (geteuid() != 0 && !no_load) {
		log_err("loading a BPF scheduler needs root (try --dry-run to check the policy)");
		return 1;
	}

	libbpf_set_print(libbpf_print);
	signal(SIGPIPE, SIG_IGN);
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	sigprocmask(SIG_BLOCK, &mask, NULL);
	sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);

restart:
	D.exiting = false;
	D.epfd = epoll_create1(EPOLL_CLOEXEC);
	if (D.epfd < 0 || sigfd < 0) {
		log_err("epoll/signalfd: %s", strerror(errno));
		return 1;
	}
	if (no_load) {
		log_warn("--no-load: control plane only, no scheduler is loaded");
		push_rule_maps(&D);
		cg_init(&D);
	} else if (load_and_attach(&D)) {
		return 1;
	}
	if (ctl_listen(&D))
		log_warn("hushctl will not be able to reach this daemon");
	if (trace_file) {
		char msg[600];

		if (trace_start(&D, trace_file, msg, sizeof(msg)))
			log_warn("%s", msg);
		trace_file = NULL;
	}

	if (D.skel)
		log_info("scx_hush loaded: %d CPUs, %d rules, %d cgroups classified, guard %llu ms, "
		 "watchdog %llu ms, inversion %s%s",
		 D.nr_cpus, D.pol.nr_rules, D.nr_cg_mapped, (unsigned long long)D.pol.p.guard_ms,
		 (unsigned long long)D.pol.p.watchdog_ms,
		 D.cfg.flags & HUSH_F_INVERSION ? "on" : "off",
		 D.cfg.flags & HUSH_F_TIER3 ? " (tiers 2+3)" : "");
	log_info("control socket %s; Ctrl-C to unload", D.sock_path);

	ecode = run_loop(&D, sigfd);

	if (D.trace) {
		char msg[600];

		trace_stop(&D, msg, sizeof(msg));
		log_info("%s", msg);
	}
	ctl_fini(&D);
	cg_fini(&D);
	detach(&D);
	if (ecode) {
		/* The kernel unloaded us (error or watchdog); say why (§11). */
		ecode = UEI_REPORT(D.skel, uei);
	}
	scx_hush__destroy(D.skel);
	D.skel = NULL;
	close(D.epfd);

	if (ecode && UEI_ECODE_RESTART(ecode)) {
		log_info("restarting after %s", "a kernel-requested reload (e.g. CPU hotplug)");
		goto restart;
	}
	log_info("scheduler unloaded; all tasks are back on the default scheduler");
	policy_free(&D.pol);
	return ecode ? 1 : 0;
}
