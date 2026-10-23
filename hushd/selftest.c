// SPDX-License-Identifier: GPL-2.0
/*
 * hushctl selftest (§8.4, §9.3): kernel feature support and the glibc mutex
 * layout tier 3 relies on. Tier 3 stays disabled unless the layout check
 * passes on this machine's glibc.
 */
#include <dlfcn.h>
#ifdef __GLIBC__
#include <gnu/libc-version.h>
#endif
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <bpf/btf.h>

#include "hushd.h"
#include "util.h"

#define FUTEX_TID_MASK 0x3fffffff
#define GLIBC_MUTEX_OWNER_OFF 8

struct lock_probe {
	pthread_mutex_t *m;
	pid_t tid;
	pthread_barrier_t locked, release;
};

static void *lock_and_hold(void *arg)
{
	struct lock_probe *lp = arg;

	pthread_mutex_lock(lp->m);
	lp->tid = (pid_t)syscall(SYS_gettid);
	pthread_barrier_wait(&lp->locked);
	pthread_barrier_wait(&lp->release);
	pthread_mutex_unlock(lp->m);
	return NULL;
}

/* Lock @m in another thread and report the owner fields seen meanwhile. */
static bool probe_mutex(pthread_mutex_t *m, uint32_t *word, int32_t *owner, pid_t *tid)
{
	struct lock_probe lp = { .m = m };
	pthread_t th;
	bool ok = false;

	pthread_barrier_init(&lp.locked, NULL, 2);
	pthread_barrier_init(&lp.release, NULL, 2);
	if (!pthread_create(&th, NULL, lock_and_hold, &lp)) {
		pthread_barrier_wait(&lp.locked);
		memcpy(word, m, sizeof(*word));
		memcpy(owner, (char *)m + GLIBC_MUTEX_OWNER_OFF, sizeof(*owner));
		*tid = lp.tid;
		pthread_barrier_wait(&lp.release);
		pthread_join(th, NULL);
		ok = true;
	}
	pthread_barrier_destroy(&lp.locked);
	pthread_barrier_destroy(&lp.release);
	return ok;
}

static const char *libc_version(void)
{
#ifdef __GLIBC__
	return gnu_get_libc_version();
#else
	return "not glibc";
#endif
}

bool selftest_glibc_layout(char *detail, size_t len)
{
	pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
	uint32_t word;
	int32_t owner, after;
	pid_t tid;

	if (sizeof(pthread_mutex_t) < GLIBC_MUTEX_OWNER_OFF + sizeof(int32_t)) {
		sfmt(detail, len, "pthread_mutex_t is only %zu bytes", sizeof(pthread_mutex_t));
		return false;
	}
	if (!probe_mutex(&m, &word, &owner, &tid)) {
		sfmt(detail, len, "could not start probe thread");
		return false;
	}
	memcpy(&after, (char *)&m + GLIBC_MUTEX_OWNER_OFF, sizeof(after));
	if (owner != tid || after != 0 || word == 0) {
		sfmt(detail, len, "owner at +%d was %d (want tid %d), %d after unlock",
		     GLIBC_MUTEX_OWNER_OFF, owner, tid, after);
		return false;
	}
	sfmt(detail, len, "__owner at offset %d holds the owner TID (glibc %s)",
	     GLIBC_MUTEX_OWNER_OFF, libc_version());
	return true;
}

static bool check_pi_futex(char *detail, size_t len)
{
	pthread_mutexattr_t a;
	pthread_mutex_t m;
	uint32_t word;
	int32_t owner;
	pid_t tid;
	bool ok;

	pthread_mutexattr_init(&a);
	if (pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_INHERIT) ||
	    pthread_mutex_init(&m, &a)) {
		sfmt(detail, len, "PTHREAD_PRIO_INHERIT mutexes unsupported");
		return false;
	}
	ok = probe_mutex(&m, &word, &owner, &tid);
	pthread_mutex_destroy(&m);
	pthread_mutexattr_destroy(&a);
	if (!ok) {
		sfmt(detail, len, "could not start probe thread");
		return false;
	}
	if ((pid_t)(word & FUTEX_TID_MASK) != tid) {
		sfmt(detail, len, "futex word 0x%x does not carry owner tid %d", word, tid);
		return false;
	}
	sfmt(detail, len, "futex word carries the owner TID (kernel ABI)");
	return true;
}

static int kernel_version(int *maj, int *min)
{
	struct utsname u;

	if (uname(&u) || sscanf(u.release, "%d.%d", maj, min) != 2)
		return -1;
	return 0;
}

static struct selftest_check *add(struct selftest_check *out, int *n, int max,
				  const char *name, bool fatal)
{
	struct selftest_check *c;

	if (*n >= max)
		return NULL;
	c = &out[(*n)++];
	memset(c, 0, sizeof(*c));
	sfmt(c->name, sizeof(c->name), "%s", name);
	c->fatal = fatal;
	return c;
}

int selftest_run(struct hushd *d, struct selftest_check *out, int max)
{
	struct selftest_check *c;
	struct btf *btf;
	struct stat st;
	char buf[128];
	int n = 0, maj = 0, min = 0;

	if ((c = add(out, &n, max, "kernel_version", true))) {
		c->ok = !kernel_version(&maj, &min) && (maj > 6 || (maj == 6 && min >= 12));
		sfmt(c->detail, sizeof(c->detail), "Linux %d.%d (need >= 6.12, NFR-7)", maj, min);
	}

	if ((c = add(out, &n, max, "sched_ext_btf", true))) {
		btf = btf__load_vmlinux_btf();
		c->ok = btf && btf__find_by_name_kind(btf, "sched_ext_ops", BTF_KIND_STRUCT) > 0;
		sfmt(c->detail, sizeof(c->detail), "%s",
		     !btf ? "no kernel BTF (/sys/kernel/btf/vmlinux)" :
		     c->ok ? "struct sched_ext_ops present" :
			     "kernel built without CONFIG_SCHED_CLASS_EXT");
		btf__free(btf);
	}

	if ((c = add(out, &n, max, "sched_ext_state", false))) {
		c->ok = read_text("/sys/kernel/sched_ext/state", buf, sizeof(buf)) > 0;
		sfmt(c->detail, sizeof(c->detail), "%s", c->ok ? buf : "/sys/kernel/sched_ext missing");
		if (c->ok && read_text("/sys/kernel/sched_ext/root/ops", buf, sizeof(buf)) > 0) {
			char tmp[sizeof(c->detail)];

			sfmt(tmp, sizeof(tmp), "%s (ops: %s)", c->detail, buf);
			sfmt(c->detail, sizeof(c->detail), "%s", tmp);
		}
	}

	if ((c = add(out, &n, max, "cgroup_v2", false))) {
		const char *root = d && d->cg_root[0] ? d->cg_root : "/sys/fs/cgroup";
		char path[PATH_MAX];

		sfmt(path, sizeof(path), "%s/cgroup.controllers", root);
		c->ok = !stat(path, &st);
		sfmt(c->detail, sizeof(c->detail), "%s %s", root,
		     c->ok ? "is cgroup v2" : "is not a cgroup v2 mount (cgroup rules inert)");
	}

	if ((c = add(out, &n, max, "tier2_pi_futex", false)))
		c->ok = check_pi_futex(c->detail, sizeof(c->detail));

	if ((c = add(out, &n, max, "tier3_glibc_layout", false))) {
		c->ok = selftest_glibc_layout(c->detail, sizeof(c->detail));
		if (!c->ok) {
			char tmp[sizeof(c->detail)];

			sfmt(tmp, sizeof(tmp), "%s; tier 3 disabled", c->detail);
			sfmt(c->detail, sizeof(c->detail), "%s", tmp);
		}
	}

	if ((c = add(out, &n, max, "tier1_libhush", false))) {
		const char *path = d ? d->pol.p.libhush_path : "libhush.so";
		void *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);

		c->ok = h && dlsym(h, "hush_critical_enter") && dlsym(h, "hush_critical_exit");
		sfmt(c->detail, sizeof(c->detail), "%s: %s", path,
		     c->ok ? "hint symbols found" : h ? "hint symbols missing" : dlerror());
		if (h)
			dlclose(h);
	}

	if (d && (c = add(out, &n, max, "guard_vs_watchdog", true))) {
		char err[256];

		c->ok = !policy_validate(&d->pol.p, err, sizeof(err));
		if (c->ok)
			sfmt(c->detail, sizeof(c->detail), "guard %llu ms <= watchdog %llu ms / 4",
			     (unsigned long long)d->pol.p.guard_ms,
			     (unsigned long long)d->pol.p.watchdog_ms);
		else
			sfmt(c->detail, sizeof(c->detail), "%s", err);
	}
	return n;
}
