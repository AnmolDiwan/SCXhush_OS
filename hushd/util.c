// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "hush_intf.h"
#include "util.h"

int hush_verbosity = LOG_INFO;

void hush_log(int level, const char *fmt, ...)
{
	static const char *const tag[] = { "error", "warn", "info", "debug" };
	va_list ap;

	if (level > hush_verbosity)
		return;
	fprintf(stderr, "hushd: %s: ", tag[level]);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

uint64_t mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int read_text(const char *path, char *buf, size_t len)
{
	ssize_t n;
	int fd;

	if (!len)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n < 0)
		return -errno;
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	buf[n] = '\0';
	return (int)n;
}

int class_from_name(const char *name)
{
	if (!strcasecmp(name, "foreground") || !strcasecmp(name, "fg"))
		return HUSH_CLASS_FG;
	if (!strcasecmp(name, "normal"))
		return HUSH_CLASS_NORMAL;
	if (!strcasecmp(name, "background") || !strcasecmp(name, "bg"))
		return HUSH_CLASS_BG;
	return 0;
}

const char *class_name(int cls)
{
	switch (cls) {
	case HUSH_CLASS_FG:
		return "FOREGROUND";
	case HUSH_CLASS_NORMAL:
		return "NORMAL";
	case HUSH_CLASS_BG:
		return "BACKGROUND";
	default:
		return "NONE";
	}
}

void sfmt(char *buf, size_t len, const char *fmt, ...)
{
	va_list ap;

	if (!len)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, len, fmt, ap);
	va_end(ap);
}
