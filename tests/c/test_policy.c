// SPDX-License-Identifier: GPL-2.0
/* Unit tests for hushd policy parsing, validation and matching. */
#include <stdio.h>
#include <string.h>

#include "policy.h"
#include "util.h"

static int failures, checks;
static const char *fixtures;

#define CHECK(cond)                                                          \
	do {                                                                 \
		checks++;                                                    \
		if (!(cond)) {                                               \
			failures++;                                          \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, \
				__LINE__, #cond);                            \
		}                                                            \
	} while (0)

static int load(const char *name, struct hush_policy *pol, char *err, size_t len)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/%s", fixtures, name);
	return policy_load(path, pol, err, len);
}

static void expect_reject(const char *name, const char *needle)
{
	struct hush_policy pol;
	char err[512] = "";
	int ret = load(name, &pol, err, sizeof(err));

	CHECK(ret != 0);
	if (ret == 0) {
		policy_free(&pol);
		return;
	}
	if (!strstr(err, needle)) {
		fprintf(stderr, "%s: error '%s' lacks '%s'\n", name, err, needle);
		failures++;
	}
	checks++;
}

static void test_good(void)
{
	struct hush_policy pol;
	struct hush_config cfg = { .policy_gen = 7 };
	struct cg_override ov[2];
	char err[512];
	int rule;

	CHECK(load("good.toml", &pol, err, sizeof(err)) == 0);
	CHECK(pol.nr_rules == 6);
	CHECK(pol.p.guard_ms == 2000);
	CHECK(pol.p.watchdog_ms == HUSH_DFL_WATCHDOG_MS);

	/* Glob on the cgroup itself and on descendants. */
	CHECK(policy_cgroup_class(&pol, NULL, 0, "/user.slice/user-1000.slice/session-3.scope", &rule) ==
	      HUSH_CLASS_FG && rule == 0);
	CHECK(policy_cgroup_class(&pol, NULL, 0, "/user.slice/user-1000.slice/session-3.scope/app", NULL) ==
	      HUSH_CLASS_FG);
	/* '*' must not cross '/'. */
	CHECK(policy_cgroup_class(&pol, NULL, 0, "/user.slice/user-1000.slice/session-a/b.scope", &rule) ==
	      HUSH_CLASS_NORMAL && rule == 4);
	CHECK(policy_cgroup_class(&pol, NULL, 0, "/system.slice/backup.service/sub", &rule) ==
	      HUSH_CLASS_BG && rule == 2);
	CHECK(policy_cgroup_class(&pol, NULL, 0, "/system.slice/sshd.service", &rule) == 0 && rule == -1);
	/* A sibling with a shared prefix is not a descendant. */
	CHECK(policy_cgroup_class(&pol, NULL, 0, "/system.slice/backup.service2", NULL) == 0);

	/* First match wins: rustc is BG (rule 2), not FG (rule 6). */
	CHECK(policy_comm_class(&pol, "rustc", &rule) == HUSH_CLASS_BG && rule == 1);
	CHECK(policy_comm_class(&pol, "bash", NULL) == 0);
	CHECK(policy_uid_class(&pol, 1002, &rule) == HUSH_CLASS_BG && rule == 3);
	CHECK(policy_uid_class(&pol, 0, NULL) == 0);

	/* Overrides beat rules; the latest override wins. */
	snprintf(ov[0].path, sizeof(ov[0].path), "/system.slice/backup.service");
	ov[0].cls = HUSH_CLASS_FG;
	snprintf(ov[1].path, sizeof(ov[1].path), "/system.slice/backup.service/sub");
	ov[1].cls = HUSH_CLASS_NORMAL;
	CHECK(policy_cgroup_class(&pol, ov, 2, "/system.slice/backup.service", &rule) == HUSH_CLASS_FG &&
	      rule == -1);
	CHECK(policy_cgroup_class(&pol, ov, 2, "/system.slice/backup.service/sub/x", NULL) ==
	      HUSH_CLASS_NORMAL);

	policy_to_config(&pol, &cfg);
	CHECK(cfg.policy_gen == 7);
	CHECK(cfg.slice_ns[HUSH_CLASS_BG] == 20000000ULL);
	CHECK(cfg.guard_ns == 2000000000ULL);
	CHECK(cfg.hard_guard_ns == HUSH_DFL_WATCHDOG_MS * 1000000ULL / 2);
	CHECK(cfg.flags & HUSH_F_INVERSION);
	CHECK(cfg.flags & HUSH_F_FALLBACK);

	policy_rule_desc(&pol, 1, err, sizeof(err));
	CHECK(strstr(err, "comm = [\"cc1\"") != NULL);
	policy_free(&pol);
}

static void test_defaults_and_ablation(void)
{
	struct hush_policy pol;
	struct hush_config cfg = {};
	char text[] = "[scheduler]\ninversion = false\n";
	char err[256];

	CHECK(policy_parse(text, &pol, err, sizeof(err)) == 0);
	CHECK(pol.nr_rules == 0);
	policy_to_config(&pol, &cfg);
	CHECK(!(cfg.flags & HUSH_F_INVERSION));
	CHECK(!(cfg.flags & HUSH_F_FALLBACK));
	CHECK(cfg.slice_ns[HUSH_CLASS_FG] == HUSH_DFL_FG_SLICE_NS);
	policy_free(&pol);
}

static void test_guard_bound(void)
{
	struct hush_params p;
	char err[256];

	policy_defaults(&p);
	p.watchdog_ms = 8000;
	p.guard_ms = 2000;
	CHECK(policy_validate(&p, err, sizeof(err)) == 0);
	p.guard_ms = 2001;
	CHECK(policy_validate(&p, err, sizeof(err)) != 0);
}

int main(int argc, char **argv)
{
	fixtures = argc > 1 ? argv[1] : "tests/c/fixtures";
	hush_verbosity = LOG_ERR;

	test_good();
	test_defaults_and_ablation();
	test_guard_bound();
	expect_reject("bad_guard.toml", "watchdog_ms/4");
	expect_reject("bad_class.toml", "unknown class 'urgent'");
	expect_reject("multi_match.toml", "exactly one of");
	expect_reject("typo.toml", "unknown key 'guard_msec'");
	expect_reject("long_comm.toml", "longer than 15");
	expect_reject("rel_cgroup.toml", "must start with '/'");
	expect_reject("guard_lt_slice.toml", "shorter than bg_slice_ms");
	expect_reject("syntax.toml", "TOML");
	expect_reject("does_not_exist.toml", "No such file");

	printf("test_policy: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
