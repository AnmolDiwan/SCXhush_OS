/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Policy file (§9.2): scheduler parameters plus ordered classification
 * rules, first match wins. Parsing and validation are pure functions with no
 * BPF dependency so they can be unit-tested and used by `hushd --dry-run`.
 */
#ifndef __HUSHD_POLICY_H
#define __HUSHD_POLICY_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hush_intf.h"

enum rule_kind { RULE_CGROUP, RULE_COMM, RULE_UID };

struct hush_rule {
	enum rule_kind kind;
	int cls;		/* HUSH_CLASS_* */
	int nr;			/* number of patterns / comms / uids */
	char **pats;		/* cgroup globs or comm names */
	uint32_t *uids;
};

struct hush_params {
	uint64_t fg_slice_ms, normal_slice_ms, bg_slice_ms;
	uint64_t guard_ms, boost_ms, watchdog_ms;
	uint64_t dstate_ms, escape_ms, fallback_ms;
	uint32_t boost_cap_pct;
	bool inversion, fallback, dstate, hints;
	char libhush_path[PATH_MAX];
};

struct hush_policy {
	struct hush_params p;
	struct hush_rule *rules;
	int nr_rules;
};

/* Runtime cgroup override from `hushctl promote/demote <cgroup>`. */
struct cg_override {
	char path[PATH_MAX];
	int cls;
};

void policy_defaults(struct hush_params *p);
int policy_parse(char *text, struct hush_policy *out, char *err, size_t errlen);
int policy_load(const char *path, struct hush_policy *out, char *err, size_t errlen);
void policy_free(struct hush_policy *pol);
/* FR-12 and range checks. Returns 0 or -EINVAL with a message. */
int policy_validate(const struct hush_params *p, char *err, size_t errlen);
void policy_to_config(const struct hush_policy *pol, struct hush_config *cfg);

/*
 * Class for a cgroup path such as "/user.slice/foo.scope". A rule (or
 * override) matches the cgroup itself or any ancestor, so rules cover whole
 * subtrees. Overrides win over rules. Returns 0 if nothing matched; *rule is
 * the rule index, or -1 for an override.
 */
int policy_cgroup_class(const struct hush_policy *pol,
			const struct cg_override *ov, int nr_ov,
			const char *path, int *rule);

/* First comm / uid rule listing @comm / @uid, or 0. */
int policy_comm_class(const struct hush_policy *pol, const char *comm, int *rule);
int policy_uid_class(const struct hush_policy *pol, uint32_t uid, int *rule);

/* Human-readable "cgroup = \"...\"" for rule @i. */
void policy_rule_desc(const struct hush_policy *pol, int i, char *buf, size_t len);

#endif
