/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hushd - scx_hush daemon and loader (§9.1).
 *
 * Owns the policy, writes the classification and config maps, reads stats
 * and the trace ring buffer back, and serves hushctl over a Unix socket.
 * With --dry-run nothing is loaded: map writes are printed instead, so the
 * policy can be checked on machines without sched_ext.
 */
#ifndef __HUSHD_H
#define __HUSHD_H

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#include "hush_intf.h"
#include "json.h"
#include "policy.h"

#define HUSHD_VERSION "0.2.0"
#define HUSHD_DFL_SOCK "/run/hush.sock"
#define HUSHD_DFL_POLICY "/etc/scx_hush/policy.toml"

enum hush_map {
	MAP_CGROUP,
	MAP_COMM,
	MAP_UID,
	MAP_PID,
	MAP_CONFIG,
};

struct cg_watch {
	char *path;		/* absolute path, NULL if the slot is free */
	uint64_t cgid;
	bool mapped;		/* has an entry in class_by_cgroup */
};

struct pid_override {
	uint32_t tgid;
	int cls;
};

struct ctl_client;
struct scx_hush;
struct bpf_link;
struct ring_buffer;

struct hushd {
	/* configuration */
	char policy_path[PATH_MAX];
	char sock_path[PATH_MAX];
	bool dry_run;
	bool no_inversion;	/* B5 ablation: no hooks, no hints */
	int stats_interval;

	/* policy state */
	struct hush_policy pol;
	struct hush_config cfg;
	struct cg_override *cg_ov;
	int nr_cg_ov;
	struct pid_override *pid_ov;
	int nr_pid_ov;
	bool tier3_ok;
	char tier3_detail[256];

	/* BPF */
	struct scx_hush *skel;
	struct bpf_link *ops_link;
	struct bpf_link *hint_links[2];
	struct ring_buffer *rb;
	int nr_cpus;

	/* cgroups */
	char cg_root[PATH_MAX];
	int inotify_fd;
	struct cg_watch *watches;	/* indexed by inotify wd */
	int nr_watches;
	int nr_cg_mapped;

	/* control socket */
	int listen_fd;
	struct ctl_client *clients;

	/* tracing */
	FILE *trace;
	char trace_path[PATH_MAX];
	uint64_t trace_events;
	uint64_t trace_lost;

	int epfd;
	uint64_t start_ns;
	volatile bool exiting;
};

/* main.c */
int hushd_map_update(struct hushd *d, enum hush_map m, const void *key, const void *val);
int hushd_map_delete(struct hushd *d, enum hush_map m, const void *key);
int hushd_push_config(struct hushd *d);
void hushd_handle(struct hushd *d, const struct json_obj *req, bool privileged, struct jw *w);

/* cgroup.c */
int cg_init(struct hushd *d);
int cg_resync(struct hushd *d);
void cg_handle_events(struct hushd *d);
void cg_fini(struct hushd *d);
/* Mount point of the cgroup v2 hierarchy. */
int cg_find_root(char *out, size_t len);
/* Path of @pid's cgroup v2 relative to the root, e.g. "/user.slice/x.scope". */
int cg_path_of_pid(int pid, char *out, size_t len);

/* ctl.c */
int ctl_listen(struct hushd *d);
void ctl_accept(struct hushd *d);
/* Returns false if @fd is not a client socket. */
bool ctl_client_event(struct hushd *d, int fd, uint32_t events);
void ctl_fini(struct hushd *d);

/* selftest.c */
struct selftest_check {
	char name[48];
	bool ok;
	bool fatal;		/* the scheduler cannot run without it */
	char detail[256];
};

#define SELFTEST_MAX 16
int selftest_run(struct hushd *d, struct selftest_check *out, int max);
bool selftest_glibc_layout(char *detail, size_t len);

#endif
