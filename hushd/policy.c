// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "policy.h"
#include "toml.h"
#include "util.h"

#define HUSH_DFL_LIBHUSH "/usr/local/lib/libhush.so"

void policy_defaults(struct hush_params *p)
{
	memset(p, 0, sizeof(*p));
	p->fg_slice_ms = HUSH_DFL_FG_SLICE_NS / 1000000;
	p->normal_slice_ms = HUSH_DFL_NORMAL_SLICE_NS / 1000000;
	p->bg_slice_ms = HUSH_DFL_BG_SLICE_NS / 1000000;
	p->guard_ms = HUSH_DFL_GUARD_NS / 1000000;
	p->boost_ms = HUSH_DFL_BOOST_NS / 1000000;
	p->boost_cap_pct = HUSH_DFL_BOOST_CAP_PCT;
	p->watchdog_ms = HUSH_DFL_WATCHDOG_MS;
	p->dstate_ms = HUSH_DFL_DSTATE_THRESH_NS / 1000000;
	p->escape_ms = HUSH_DFL_ESCAPE_NS / 1000000;
	p->fallback_ms = HUSH_DFL_FALLBACK_WINDOW_NS / 1000000;
	p->inversion = true;
	p->fallback = true;
	p->dstate = true;
	p->hints = true;
	snprintf(p->libhush_path, sizeof(p->libhush_path), "%s", HUSH_DFL_LIBHUSH);
}

void policy_free(struct hush_policy *pol)
{
	for (int i = 0; i < pol->nr_rules; i++) {
		struct hush_rule *r = &pol->rules[i];

		for (int j = 0; r->pats && j < r->nr; j++)
			free(r->pats[j]);
		free(r->pats);
		free(r->uids);
	}
	free(pol->rules);
	pol->rules = NULL;
	pol->nr_rules = 0;
}

static int fail(char *err, size_t errlen, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static int fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return -EINVAL;
}

/* [scheduler] keys: name, target, and whether it is a bool. */
struct param_key {
	const char *name;
	size_t off;
	enum { P_U64, P_U32, P_BOOL, P_STR } type;
};

#define PK(n, t) { #n, offsetof(struct hush_params, n), t }
static const struct param_key param_keys[] = {
	PK(fg_slice_ms, P_U64),
	PK(normal_slice_ms, P_U64),
	PK(bg_slice_ms, P_U64),
	PK(guard_ms, P_U64),
	PK(boost_ms, P_U64),
	PK(watchdog_ms, P_U64),
	PK(dstate_ms, P_U64),
	PK(escape_ms, P_U64),
	PK(fallback_ms, P_U64),
	PK(boost_cap_pct, P_U32),
	PK(inversion, P_BOOL),
	PK(fallback, P_BOOL),
	PK(dstate, P_BOOL),
	PK(hints, P_BOOL),
	PK(libhush_path, P_STR),
};

static int parse_params(toml_table_t *t, struct hush_params *p, char *err, size_t errlen)
{
	const char *key;

	for (int i = 0; (key = toml_key_in(t, i)); i++) {
		const struct param_key *pk = NULL;
		toml_datum_t d;

		for (size_t k = 0; k < sizeof(param_keys) / sizeof(param_keys[0]); k++)
			if (!strcmp(param_keys[k].name, key))
				pk = &param_keys[k];
		if (!pk)
			return fail(err, errlen, "[scheduler]: unknown key '%s'", key);

		switch (pk->type) {
		case P_U64:
		case P_U32:
			d = toml_int_in(t, key);
			if (!d.ok || d.u.i < 0)
				return fail(err, errlen, "[scheduler]: '%s' must be a non-negative integer", key);
			if (pk->type == P_U64)
				*(uint64_t *)((char *)p + pk->off) = (uint64_t)d.u.i;
			else
				*(uint32_t *)((char *)p + pk->off) = (uint32_t)d.u.i;
			break;
		case P_BOOL:
			d = toml_bool_in(t, key);
			if (!d.ok)
				return fail(err, errlen, "[scheduler]: '%s' must be true or false", key);
			*(bool *)((char *)p + pk->off) = d.u.b;
			break;
		case P_STR:
			d = toml_string_in(t, key);
			if (!d.ok)
				return fail(err, errlen, "[scheduler]: '%s' must be a string", key);
			snprintf((char *)p + pk->off, PATH_MAX, "%s", d.u.s);
			free(d.u.s);
			break;
		}
	}
	return 0;
}

/* A match value is a string/int or an array of them. */
static int parse_match_values(toml_table_t *m, const char *key, struct hush_rule *r,
			      int idx, char *err, size_t errlen)
{
	toml_array_t *arr = toml_array_in(m, key);
	bool is_uid = r->kind == RULE_UID;
	int n = arr ? toml_array_nelem(arr) : 1;

	if (n <= 0)
		return fail(err, errlen, "rule %d: '%s' list is empty", idx, key);
	if (is_uid)
		r->uids = calloc(n, sizeof(*r->uids));
	else
		r->pats = calloc(n, sizeof(*r->pats));
	if ((is_uid && !r->uids) || (!is_uid && !r->pats))
		return -ENOMEM;

	for (int i = 0; i < n; i++) {
		toml_datum_t d;

		if (is_uid) {
			d = arr ? toml_int_at(arr, i) : toml_int_in(m, key);
			if (!d.ok || d.u.i < 0 || d.u.i > UINT32_MAX)
				return fail(err, errlen, "rule %d: uid must be a non-negative integer", idx);
			r->uids[i] = (uint32_t)d.u.i;
		} else {
			d = arr ? toml_string_at(arr, i) : toml_string_in(m, key);
			if (!d.ok)
				return fail(err, errlen, "rule %d: '%s' must be a string or list of strings", idx, key);
			r->pats[i] = d.u.s;
			if (r->kind == RULE_COMM && strlen(d.u.s) >= HUSH_COMM_LEN)
				return fail(err, errlen,
					    "rule %d: comm '%s' longer than %d characters (the kernel truncates comm)",
					    idx, d.u.s, HUSH_COMM_LEN - 1);
			if (r->kind == RULE_CGROUP && d.u.s[0] != '/')
				return fail(err, errlen, "rule %d: cgroup '%s' must start with '/'", idx, d.u.s);
		}
		r->nr = i + 1;
	}
	return 0;
}

static int parse_rule(toml_table_t *t, int idx, struct hush_rule *r, char *err, size_t errlen)
{
	static const struct { const char *key; enum rule_kind kind; } kinds[] = {
		{ "cgroup", RULE_CGROUP }, { "comm", RULE_COMM }, { "uid", RULE_UID },
	};
	toml_table_t *m = toml_table_in(t, "match");
	toml_datum_t cls = toml_string_in(t, "class");
	const char *key, *mkey = NULL;
	int ret;

	for (int i = 0; (key = toml_key_in(t, i)); i++)
		if (strcmp(key, "match") && strcmp(key, "class"))
			return fail(err, errlen, "rule %d: unknown key '%s'", idx, key);
	if (!cls.ok)
		return fail(err, errlen, "rule %d: missing class", idx);
	r->cls = class_from_name(cls.u.s);
	if (!r->cls) {
		ret = fail(err, errlen, "rule %d: unknown class '%s' (foreground, normal, background)",
			   idx, cls.u.s);
		free(cls.u.s);
		return ret;
	}
	free(cls.u.s);
	if (!m)
		return fail(err, errlen, "rule %d: missing match table", idx);

	for (int i = 0; (key = toml_key_in(m, i)); i++) {
		if (mkey)
			return fail(err, errlen,
				    "rule %d: match on exactly one of cgroup, comm, uid (got '%s' and '%s')",
				    idx, mkey, key);
		mkey = key;
	}
	if (!mkey)
		return fail(err, errlen, "rule %d: empty match", idx);
	for (size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); k++) {
		if (!strcmp(kinds[k].key, mkey)) {
			r->kind = kinds[k].kind;
			return parse_match_values(m, mkey, r, idx, err, errlen);
		}
	}
	return fail(err, errlen, "rule %d: unknown match key '%s' (cgroup, comm, uid)", idx, mkey);
}

int policy_parse(char *text, struct hush_policy *out, char *err, size_t errlen)
{
	char terr[256];
	toml_table_t *root, *sched;
	toml_array_t *rules;
	const char *key;
	int ret = 0;

	memset(out, 0, sizeof(*out));
	policy_defaults(&out->p);

	root = toml_parse(text, terr, sizeof(terr));
	if (!root)
		return fail(err, errlen, "TOML: %s", terr);

	for (int i = 0; (key = toml_key_in(root, i)); i++) {
		if (strcmp(key, "scheduler") && strcmp(key, "rule")) {
			ret = fail(err, errlen, "unknown top-level key '%s'", key);
			goto out;
		}
	}

	sched = toml_table_in(root, "scheduler");
	if (sched && (ret = parse_params(sched, &out->p, err, errlen)))
		goto out;

	rules = toml_array_in(root, "rule");
	if (rules) {
		int n = toml_array_nelem(rules);

		if (toml_array_kind(rules) != 't') {
			ret = fail(err, errlen, "'rule' must be an array of tables ([[rule]])");
			goto out;
		}
		out->rules = calloc(n ? n : 1, sizeof(*out->rules));
		if (!out->rules) {
			ret = -ENOMEM;
			goto out;
		}
		for (int i = 0; i < n; i++) {
			out->nr_rules = i + 1;
			ret = parse_rule(toml_table_at(rules, i), i + 1, &out->rules[i], err, errlen);
			if (ret)
				goto out;
		}
	}

	ret = policy_validate(&out->p, err, errlen);
out:
	toml_free(root);
	if (ret)
		policy_free(out);
	return ret;
}

int policy_load(const char *path, struct hush_policy *out, char *err, size_t errlen)
{
	FILE *f = fopen(path, "re");
	char *text;
	long len;
	int ret;

	if (!f)
		return fail(err, errlen, "%s: %s", path, strerror(errno));
	if (fseek(f, 0, SEEK_END) || (len = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
		fclose(f);
		return fail(err, errlen, "%s: cannot size file", path);
	}
	if (len > 1 << 20) {
		fclose(f);
		return fail(err, errlen, "%s: larger than 1 MiB", path);
	}
	text = malloc(len + 1);
	if (!text) {
		fclose(f);
		return -ENOMEM;
	}
	if (fread(text, 1, len, f) != (size_t)len) {
		free(text);
		fclose(f);
		return fail(err, errlen, "%s: read error", path);
	}
	text[len] = '\0';
	fclose(f);

	ret = policy_parse(text, out, err, errlen);
	if (ret) {
		/* Prefix the file name for the operator. */
		char tmp[512];

		snprintf(tmp, sizeof(tmp), "%s: %s", path, err);
		snprintf(err, errlen, "%s", tmp);
	}
	free(text);
	return ret;
}

#define RANGE(field, lo, hi)							\
	do {									\
		if (p->field < (lo) || p->field > (hi))				\
			return fail(err, errlen, #field " = %llu is outside [%llu, %llu]", \
				    (unsigned long long)p->field,		\
				    (unsigned long long)(lo), (unsigned long long)(hi)); \
	} while (0)

int policy_validate(const struct hush_params *p, char *err, size_t errlen)
{
	RANGE(fg_slice_ms, 1, 1000);
	RANGE(normal_slice_ms, 1, 1000);
	RANGE(bg_slice_ms, 1, 1000);
	/* sched_ext accepts at most 30 s; below 1 s the guard has no room. */
	RANGE(watchdog_ms, 1000, 30000);
	RANGE(boost_ms, 1, 1000);
	RANGE(boost_cap_pct, 1, 100);
	RANGE(dstate_ms, 1, 1000);
	RANGE(escape_ms, 1, 1000);
	RANGE(fallback_ms, 1, 1000);

	/* FR-12 / §7.5: far below the watchdog, or the kernel ejects us. */
	if (p->guard_ms * 4 > p->watchdog_ms)
		return fail(err, errlen,
			    "guard_ms = %llu exceeds watchdog_ms/4 = %llu; the sched_ext watchdog "
			    "would see a stalled runnable task and abort the scheduler",
			    (unsigned long long)p->guard_ms,
			    (unsigned long long)(p->watchdog_ms / 4));
	if (p->guard_ms < p->bg_slice_ms)
		return fail(err, errlen,
			    "guard_ms = %llu is shorter than bg_slice_ms = %llu; the guard would "
			    "hand out more than one background slice per interval",
			    (unsigned long long)p->guard_ms, (unsigned long long)p->bg_slice_ms);
	return 0;
}

void policy_to_config(const struct hush_policy *pol, struct hush_config *cfg)
{
	const struct hush_params *p = &pol->p;
	uint32_t gen = cfg->policy_gen;

	memset(cfg, 0, sizeof(*cfg));
	cfg->slice_ns[HUSH_CLASS_FG] = p->fg_slice_ms * 1000000ULL;
	cfg->slice_ns[HUSH_CLASS_NORMAL] = p->normal_slice_ms * 1000000ULL;
	cfg->slice_ns[HUSH_CLASS_BG] = p->bg_slice_ms * 1000000ULL;
	cfg->guard_ns = p->guard_ms * 1000000ULL;
	cfg->hard_guard_ns = p->watchdog_ms * 1000000ULL / 2;
	cfg->boost_ns = p->boost_ms * 1000000ULL;
	cfg->dstate_thresh_ns = p->dstate_ms * 1000000ULL;
	cfg->escape_ns = p->escape_ms * 1000000ULL;
	cfg->fallback_window_ns = p->fallback_ms * 1000000ULL;
	cfg->boost_cap_pct = p->boost_cap_pct;
	cfg->policy_gen = gen;
	if (p->inversion)
		cfg->flags |= HUSH_F_INVERSION;
	if (p->inversion && p->fallback)
		cfg->flags |= HUSH_F_FALLBACK;
	if (p->dstate)
		cfg->flags |= HUSH_F_DSTATE;
	if (p->hints)
		cfg->flags |= HUSH_F_HINTS;
}

/* Does @pat match @path or one of its ancestors? */
static bool cgroup_match(const char *pat, const char *path)
{
	char buf[PATH_MAX];
	char *slash;

	snprintf(buf, sizeof(buf), "%s", path);
	for (;;) {
		if (!fnmatch(pat, buf, FNM_PATHNAME))
			return true;
		slash = strrchr(buf, '/');
		if (!slash || slash == buf)
			break;
		*slash = '\0';
	}
	return !strcmp(pat, "/");
}

int policy_cgroup_class(const struct hush_policy *pol, const struct cg_override *ov,
			int nr_ov, const char *path, int *rule)
{
	if (rule)
		*rule = -1;
	/* The most recent override wins. */
	for (int i = nr_ov - 1; i >= 0; i--)
		if (cgroup_match(ov[i].path, path))
			return ov[i].cls;
	for (int i = 0; i < pol->nr_rules; i++) {
		const struct hush_rule *r = &pol->rules[i];

		if (r->kind != RULE_CGROUP)
			continue;
		for (int j = 0; j < r->nr; j++) {
			if (cgroup_match(r->pats[j], path)) {
				if (rule)
					*rule = i;
				return r->cls;
			}
		}
	}
	return 0;
}

int policy_comm_class(const struct hush_policy *pol, const char *comm, int *rule)
{
	for (int i = 0; i < pol->nr_rules; i++) {
		const struct hush_rule *r = &pol->rules[i];

		if (r->kind != RULE_COMM)
			continue;
		for (int j = 0; j < r->nr; j++) {
			if (!strcmp(r->pats[j], comm)) {
				if (rule)
					*rule = i;
				return r->cls;
			}
		}
	}
	return 0;
}

int policy_uid_class(const struct hush_policy *pol, uint32_t uid, int *rule)
{
	for (int i = 0; i < pol->nr_rules; i++) {
		const struct hush_rule *r = &pol->rules[i];

		if (r->kind != RULE_UID)
			continue;
		for (int j = 0; j < r->nr; j++) {
			if (r->uids[j] == uid) {
				if (rule)
					*rule = i;
				return r->cls;
			}
		}
	}
	return 0;
}

void policy_rule_desc(const struct hush_policy *pol, int i, char *buf, size_t len)
{
	static const char *const kind[] = { "cgroup", "comm", "uid" };
	const struct hush_rule *r;
	size_t off;

	if (i < 0 || i >= pol->nr_rules) {
		snprintf(buf, len, "?");
		return;
	}
	r = &pol->rules[i];
	off = snprintf(buf, len, "rule #%d: %s = [", i + 1, kind[r->kind]);
	for (int j = 0; j < r->nr && off < len; j++) {
		if (r->kind == RULE_UID)
			off += snprintf(buf + off, len - off, "%s%u", j ? ", " : "", r->uids[j]);
		else
			off += snprintf(buf + off, len - off, "%s\"%s\"", j ? ", " : "", r->pats[j]);
	}
	if (off < len)
		snprintf(buf + off, len - off, "] -> %s", class_name(r->cls));
}
