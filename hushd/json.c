// SPDX-License-Identifier: GPL-2.0
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

struct jp {
	const char *s;
	char *err;
	size_t errlen;
	int depth;
};

static int jp_fail(struct jp *p, const char *msg)
{
	snprintf(p->err, p->errlen, "%s", msg);
	return -EINVAL;
}

static void jp_ws(struct jp *p)
{
	while (isspace((unsigned char)*p->s))
		p->s++;
}

static int jp_string(struct jp *p, char *out, size_t outlen)
{
	size_t n = 0;

	if (*p->s != '"')
		return jp_fail(p, "expected string");
	p->s++;
	while (*p->s && *p->s != '"') {
		char c = *p->s++;

		if (c == '\\') {
			c = *p->s++;
			switch (c) {
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case '"': case '\\': case '/': break;
			case 'u':
				/* Keep ASCII only; replace anything else. */
				if (!isxdigit((unsigned char)p->s[0]) || !isxdigit((unsigned char)p->s[1]) ||
				    !isxdigit((unsigned char)p->s[2]) || !isxdigit((unsigned char)p->s[3]))
					return jp_fail(p, "bad \\u escape");
				{
					char hex[5] = { p->s[0], p->s[1], p->s[2], p->s[3], 0 };
					long v = strtol(hex, NULL, 16);

					c = v < 0x80 ? (char)v : '?';
				}
				p->s += 4;
				break;
			default:
				return jp_fail(p, "bad escape");
			}
		}
		if (n + 1 >= outlen)
			return jp_fail(p, "string too long");
		out[n++] = c;
	}
	if (*p->s != '"')
		return jp_fail(p, "unterminated string");
	p->s++;
	out[n] = '\0';
	return 0;
}

static int jp_object(struct jp *p, struct json_obj *o);

static int jp_value(struct jp *p, struct json_val *v)
{
	char *end;

	jp_ws(p);
	memset(v, 0, sizeof(*v));
	switch (*p->s) {
	case '"':
		v->type = J_STR;
		return jp_string(p, v->str, sizeof(v->str));
	case '{':
		if (p->depth >= 2)
			return jp_fail(p, "objects nested too deep");
		v->type = J_OBJ;
		v->obj = calloc(1, sizeof(*v->obj));
		if (!v->obj)
			return -ENOMEM;
		return jp_object(p, v->obj);
	case 't':
		if (strncmp(p->s, "true", 4))
			return jp_fail(p, "bad literal");
		p->s += 4;
		v->type = J_BOOL;
		v->b = true;
		return 0;
	case 'f':
		if (strncmp(p->s, "false", 5))
			return jp_fail(p, "bad literal");
		p->s += 5;
		v->type = J_BOOL;
		return 0;
	case 'n':
		if (strncmp(p->s, "null", 4))
			return jp_fail(p, "bad literal");
		p->s += 4;
		v->type = J_NULL;
		return 0;
	default:
		v->num = strtod(p->s, &end);
		if (end == p->s)
			return jp_fail(p, "unexpected character");
		p->s = end;
		v->type = J_NUM;
		return 0;
	}
}

static int jp_object(struct jp *p, struct json_obj *o)
{
	int ret;

	jp_ws(p);
	if (*p->s != '{')
		return jp_fail(p, "expected object");
	p->s++;
	p->depth++;
	jp_ws(p);
	if (*p->s == '}') {
		p->s++;
		p->depth--;
		return 0;
	}
	for (;;) {
		if (o->n >= JSON_MAX_FIELDS)
			return jp_fail(p, "too many fields");
		jp_ws(p);
		ret = jp_string(p, o->key[o->n], sizeof(o->key[0]));
		if (ret)
			return ret;
		jp_ws(p);
		if (*p->s != ':')
			return jp_fail(p, "expected ':'");
		p->s++;
		ret = jp_value(p, &o->val[o->n]);
		o->n++;
		if (ret)
			return ret;
		jp_ws(p);
		if (*p->s == ',') {
			p->s++;
			continue;
		}
		if (*p->s == '}') {
			p->s++;
			p->depth--;
			return 0;
		}
		return jp_fail(p, "expected ',' or '}'");
	}
}

int json_parse(const char *text, struct json_obj *out, char *err, size_t errlen)
{
	struct jp p = { .s = text, .err = err, .errlen = errlen };
	int ret;

	memset(out, 0, sizeof(*out));
	ret = jp_object(&p, out);
	if (!ret) {
		jp_ws(&p);
		if (*p.s)
			ret = jp_fail(&p, "trailing characters");
	}
	if (ret)
		json_free(out);
	return ret;
}

void json_free(struct json_obj *o)
{
	for (int i = 0; i < o->n; i++) {
		if (o->val[i].type == J_OBJ && o->val[i].obj) {
			json_free(o->val[i].obj);
			free(o->val[i].obj);
			o->val[i].obj = NULL;
		}
	}
	o->n = 0;
}

const struct json_val *json_get(const struct json_obj *o, const char *key)
{
	if (!o)
		return NULL;
	for (int i = 0; i < o->n; i++)
		if (!strcmp(o->key[i], key))
			return &o->val[i];
	return NULL;
}

const char *json_get_str(const struct json_obj *o, const char *key)
{
	const struct json_val *v = json_get(o, key);

	return v && v->type == J_STR ? v->str : NULL;
}

const struct json_obj *json_get_obj(const struct json_obj *o, const char *key)
{
	const struct json_val *v = json_get(o, key);

	return v && v->type == J_OBJ ? v->obj : NULL;
}

bool json_get_i64(const struct json_obj *o, const char *key, int64_t *out)
{
	const struct json_val *v = json_get(o, key);
	char *end;

	if (!v)
		return false;
	if (v->type == J_NUM) {
		*out = (int64_t)v->num;
		return (double)*out == v->num;
	}
	if (v->type == J_STR && v->str[0]) {
		errno = 0;
		*out = strtoll(v->str, &end, 10);
		return !errno && !*end;
	}
	return false;
}

/* ---------------------------------------------------------------- writer */

static void jw_raw(struct jw *w, const char *s, size_t n)
{
	if (w->oom)
		return;
	if (w->len + n + 1 > w->cap) {
		size_t cap = w->cap ? w->cap * 2 : 1024;
		char *nb;

		while (cap < w->len + n + 1)
			cap *= 2;
		nb = realloc(w->buf, cap);
		if (!nb) {
			w->oom = true;
			return;
		}
		w->buf = nb;
		w->cap = cap;
	}
	memcpy(w->buf + w->len, s, n);
	w->len += n;
	w->buf[w->len] = '\0';
}

static void jw_puts(struct jw *w, const char *s)
{
	jw_raw(w, s, strlen(s));
}

static void jw_escaped(struct jw *w, const char *s)
{
	char esc[8];

	jw_raw(w, "\"", 1);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\') {
			esc[0] = '\\';
			esc[1] = (char)c;
			jw_raw(w, esc, 2);
		} else if (c < 0x20) {
			snprintf(esc, sizeof(esc), "\\u%04x", c);
			jw_puts(w, esc);
		} else {
			jw_raw(w, (const char *)&c, 1);
		}
	}
	jw_raw(w, "\"", 1);
}

static void jw_key(struct jw *w, const char *key)
{
	if (w->need_comma)
		jw_raw(w, ",", 1);
	w->need_comma = true;
	if (key) {
		jw_escaped(w, key);
		jw_raw(w, ":", 1);
	}
}

void jw_init(struct jw *w)
{
	memset(w, 0, sizeof(*w));
}

void jw_free(struct jw *w)
{
	free(w->buf);
	memset(w, 0, sizeof(*w));
}

void jw_obj_begin(struct jw *w, const char *key)
{
	jw_key(w, key);
	jw_raw(w, "{", 1);
	w->need_comma = false;
}

void jw_obj_end(struct jw *w)
{
	jw_raw(w, "}", 1);
	w->need_comma = true;
}

void jw_arr_begin(struct jw *w, const char *key)
{
	jw_key(w, key);
	jw_raw(w, "[", 1);
	w->need_comma = false;
}

void jw_arr_end(struct jw *w)
{
	jw_raw(w, "]", 1);
	w->need_comma = true;
}

void jw_str(struct jw *w, const char *key, const char *val)
{
	jw_key(w, key);
	jw_escaped(w, val ? val : "");
}

void jw_u64(struct jw *w, const char *key, uint64_t val)
{
	char num[32];

	jw_key(w, key);
	snprintf(num, sizeof(num), "%llu", (unsigned long long)val);
	jw_puts(w, num);
}

void jw_i64(struct jw *w, const char *key, int64_t val)
{
	char num[32];

	jw_key(w, key);
	snprintf(num, sizeof(num), "%lld", (long long)val);
	jw_puts(w, num);
}

void jw_dbl(struct jw *w, const char *key, double val)
{
	char num[64];

	jw_key(w, key);
	snprintf(num, sizeof(num), "%.6g", val);
	jw_puts(w, num);
}

void jw_bool(struct jw *w, const char *key, bool val)
{
	jw_key(w, key);
	jw_puts(w, val ? "true" : "false");
}
