/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal JSON for the control socket (§10.4: newline-delimited JSON).
 *
 * Requests are a single object whose values are strings, numbers, booleans,
 * null or one level of nested object ("args"). The parser is deliberately
 * small and bounded; anything outside that shape is rejected.
 */
#ifndef __HUSHD_JSON_H
#define __HUSHD_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_FIELDS 16
#define JSON_MAX_STR 512

enum json_type { J_NULL, J_BOOL, J_NUM, J_STR, J_OBJ };

struct json_obj;

struct json_val {
	enum json_type type;
	bool b;
	double num;
	char str[JSON_MAX_STR];
	struct json_obj *obj;
};

struct json_obj {
	int n;
	char key[JSON_MAX_FIELDS][64];
	struct json_val val[JSON_MAX_FIELDS];
};

/* Parse @text into @out; nested objects are allocated and freed by json_free(). */
int json_parse(const char *text, struct json_obj *out, char *err, size_t errlen);
void json_free(struct json_obj *o);

const struct json_val *json_get(const struct json_obj *o, const char *key);
const char *json_get_str(const struct json_obj *o, const char *key);
const struct json_obj *json_get_obj(const struct json_obj *o, const char *key);
/* Accepts a number or a numeric string. Returns false if absent or invalid. */
bool json_get_i64(const struct json_obj *o, const char *key, int64_t *out);

/* Append-only JSON writer into a growable buffer. */
struct jw {
	char *buf;
	size_t len, cap;
	bool need_comma;
	bool oom;
};

void jw_init(struct jw *w);
void jw_free(struct jw *w);
void jw_obj_begin(struct jw *w, const char *key);
void jw_obj_end(struct jw *w);
void jw_arr_begin(struct jw *w, const char *key);
void jw_arr_end(struct jw *w);
void jw_str(struct jw *w, const char *key, const char *val);
void jw_u64(struct jw *w, const char *key, uint64_t val);
void jw_i64(struct jw *w, const char *key, int64_t val);
void jw_dbl(struct jw *w, const char *key, double val);
void jw_bool(struct jw *w, const char *key, bool val);

#endif
