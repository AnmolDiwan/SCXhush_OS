// SPDX-License-Identifier: GPL-2.0
/*
 * Cgroup v2 resolution (FR-2): walk the hierarchy, evaluate the policy for
 * every cgroup and store the resulting class per cgroup ID, so the BPF side
 * does one hash lookup per classification. inotify keeps the map current
 * as systemd creates and removes scopes.
 */
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hushd.h"
#include "util.h"

#define CG_WATCH_MASK (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM | IN_ONLYDIR)

static struct hushd *walk_d;	/* nftw has no user pointer */

static const char *rel_path(struct hushd *d, const char *abs)
{
	size_t n = strlen(d->cg_root);
	const char *rel = abs + n;

	return *rel ? rel : "/";
}

static uint64_t cgroup_id(const char *path)
{
	struct {
		struct file_handle fh;
		uint64_t id;
	} h;
	struct stat st;
	int mount_id;

	h.fh.handle_bytes = sizeof(h.id);
	if (!name_to_handle_at(AT_FDCWD, path, &h.fh, &mount_id, 0) &&
	    h.fh.handle_bytes == sizeof(h.id))
		return h.id;
	return stat(path, &st) ? 0 : (uint64_t)st.st_ino;
}

static int find_root(char *out, size_t len)
{
	struct mntent *m;
	FILE *f = setmntent("/proc/self/mounts", "re");

	if (!f)
		return -errno;
	while ((m = getmntent(f))) {
		if (!strcmp(m->mnt_type, "cgroup2")) {
			sfmt(out, len, "%s", m->mnt_dir);
			endmntent(f);
			return 0;
		}
	}
	endmntent(f);
	return -ENOENT;
}

static struct cg_watch *watch_slot(struct hushd *d, int wd)
{
	if (wd >= d->nr_watches) {
		int n = d->nr_watches ? d->nr_watches : 256;
		struct cg_watch *w;

		while (n <= wd)
			n *= 2;
		w = realloc(d->watches, n * sizeof(*w));
		if (!w)
			return NULL;
		memset(w + d->nr_watches, 0, (n - d->nr_watches) * sizeof(*w));
		d->watches = w;
		d->nr_watches = n;
	}
	return &d->watches[wd];
}

static void cg_set(struct hushd *d, struct cg_watch *w, const char *abs)
{
	uint8_t cls = policy_cgroup_class(&d->pol, d->cg_ov, d->nr_cg_ov, rel_path(d, abs), NULL);

	if (cls && d->dry_run && !w->mapped)
		printf("  cgroup %-56s -> %s\n", rel_path(d, abs), class_name(cls));
	if (cls) {
		if (!hushd_map_update(d, MAP_CGROUP, &w->cgid, &cls)) {
			if (!w->mapped)
				d->nr_cg_mapped++;
			w->mapped = true;
		}
	} else if (w->mapped) {
		hushd_map_delete(d, MAP_CGROUP, &w->cgid);
		w->mapped = false;
		d->nr_cg_mapped--;
	}
}

static void visit_dir(struct hushd *d, const char *abs)
{
	struct cg_watch *w;
	int wd;

	wd = d->inotify_fd >= 0 ? inotify_add_watch(d->inotify_fd, abs, CG_WATCH_MASK) : -1;
	if (wd < 0) {
		/* No inotify (or watch limit hit): classify once, no updates. */
		static int warned;
		struct cg_watch tmp = { .cgid = cgroup_id(abs) };

		if (d->inotify_fd >= 0 && !warned++)
			log_warn("inotify_add_watch(%s): %s; new cgroups below it will not be "
				 "classified until reload", abs, strerror(errno));
		if (tmp.cgid)
			cg_set(d, &tmp, abs);
		return;
	}
	w = watch_slot(d, wd);
	if (!w)
		return;
	if (!w->path) {
		w->path = strdup(abs);
		w->cgid = cgroup_id(abs);
	}
	if (w->cgid)
		cg_set(d, w, abs);
}

static int walk_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
	if (type == FTW_D)
		visit_dir(walk_d, path);
	return 0;
}

static void walk(struct hushd *d, const char *from)
{
	walk_d = d;
	if (nftw(from, walk_cb, 32, FTW_PHYS | FTW_MOUNT) && errno != ENOENT)
		log_warn("walking %s: %s", from, strerror(errno));
}

int cg_init(struct hushd *d)
{
	int ret = d->cg_root[0] ? 0 : find_root(d->cg_root, sizeof(d->cg_root));

	if (ret) {
		log_err("no cgroup v2 mount found; cgroup rules cannot be applied");
		return ret;
	}
	/* "/sys/fs/cgroup/" and "/sys/fs/cgroup" must give the same rel paths. */
	for (size_t n = strlen(d->cg_root); n > 1 && d->cg_root[n - 1] == '/'; n--)
		d->cg_root[n - 1] = '\0';

	d->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (d->inotify_fd < 0)
		log_warn("inotify_init1: %s; new cgroups need 'hushctl reload'", strerror(errno));
	return cg_resync(d);
}

int cg_resync(struct hushd *d)
{
	walk(d, d->cg_root);
	if (d->nr_cg_mapped > HUSH_MAP_CGROUP_MAX)
		log_warn("%d cgroups classified, more than class_by_cgroup holds (%d)",
			 d->nr_cg_mapped, HUSH_MAP_CGROUP_MAX);
	log_debug("cgroups: %d classified under %s", d->nr_cg_mapped, d->cg_root);
	return 0;
}

static void forget(struct hushd *d, int wd)
{
	struct cg_watch *w;

	if (wd < 0 || wd >= d->nr_watches)
		return;
	w = &d->watches[wd];
	if (w->mapped) {
		hushd_map_delete(d, MAP_CGROUP, &w->cgid);
		d->nr_cg_mapped--;
	}
	free(w->path);
	memset(w, 0, sizeof(*w));
}

void cg_handle_events(struct hushd *d)
{
	char buf[16384] __attribute__((aligned(__alignof__(struct inotify_event))));
	char path[PATH_MAX];
	ssize_t n;

	while ((n = read(d->inotify_fd, buf, sizeof(buf))) > 0) {
		for (char *p = buf; p < buf + n;) {
			struct inotify_event *ev = (struct inotify_event *)p;
			struct cg_watch *parent;

			p += sizeof(*ev) + ev->len;
			if (ev->mask & IN_Q_OVERFLOW) {
				log_warn("inotify queue overflow; rescanning cgroups");
				cg_resync(d);
				continue;
			}
			if (ev->mask & IN_IGNORED) {
				forget(d, ev->wd);
				continue;
			}
			if (!(ev->mask & IN_ISDIR) || !ev->len || ev->wd >= d->nr_watches)
				continue;
			parent = &d->watches[ev->wd];
			if (!parent->path)
				continue;
			sfmt(path, sizeof(path), "%s/%s", parent->path, ev->name);

			if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
				log_debug("cgroup created: %s", rel_path(d, path));
				walk(d, path);
			}
			/*
			 * Deleted cgroups also deliver IN_IGNORED on their own
			 * watch, which drops the map entry via forget().
			 */
		}
	}
}

void cg_fini(struct hushd *d)
{
	for (int i = 0; i < d->nr_watches; i++)
		free(d->watches[i].path);
	free(d->watches);
	d->watches = NULL;
	d->nr_watches = 0;
	if (d->inotify_fd >= 0)
		close(d->inotify_fd);
	d->inotify_fd = -1;
}

int cg_path_of_pid(int pid, char *out, size_t len)
{
	char path[64], line[PATH_MAX + 16];
	FILE *f;

	sfmt(path, sizeof(path), "/proc/%d/cgroup", pid);
	f = fopen(path, "re");
	if (!f)
		return -errno;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "0::", 3)) {
			line[strcspn(line, "\n")] = '\0';
			sfmt(out, len, "%s", line + 3);
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -ENOENT;
}
