/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __HUSHD_UTIL_H
#define __HUSHD_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { LOG_ERR, LOG_WARN, LOG_INFO, LOG_DEBUG };

extern int hush_verbosity;

void hush_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define log_err(...) hush_log(LOG_ERR, __VA_ARGS__)
#define log_warn(...) hush_log(LOG_WARN, __VA_ARGS__)
#define log_info(...) hush_log(LOG_INFO, __VA_ARGS__)
#define log_debug(...) hush_log(LOG_DEBUG, __VA_ARGS__)

/* CLOCK_MONOTONIC in ns: the same clock as bpf_ktime_get_ns(). */
uint64_t mono_ns(void);

/* Read a small text file, strip the trailing newline. Returns length or -errno. */
int read_text(const char *path, char *buf, size_t len);

/* "foreground"/"fg" -> HUSH_CLASS_FG etc. Returns 0 if unknown. */
int class_from_name(const char *name);
const char *class_name(int cls);

/* snprintf into a fixed buffer, always NUL-terminated, never fails. */
void sfmt(char *buf, size_t len, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#endif
