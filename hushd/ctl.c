// SPDX-License-Identifier: GPL-2.0
/*
 * Control socket (§10.4): Unix socket, one JSON request per line, one JSON
 * reply per line. Anyone may read status; only root (SO_PEERCRED) may change
 * classes, reload, trace or run the selftest.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "hushd.h"
#include "util.h"

#define CTL_BUF 8192
#define CTL_MAX_CLIENTS 64

struct ctl_client {
	int fd;
	bool privileged;
	size_t len;
	char buf[CTL_BUF];
	struct ctl_client *next;
};

static int nr_clients;

int ctl_listen(struct hushd *d)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct epoll_event ev = { .events = EPOLLIN };
	int fd;

	if (strlen(d->sock_path) >= sizeof(addr.sun_path)) {
		log_err("socket path too long: %s", d->sock_path);
		return -ENAMETOOLONG;
	}
	strcpy(addr.sun_path, d->sock_path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	unlink(d->sock_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || listen(fd, 16)) {
		int err = -errno;

		log_err("control socket %s: %s", d->sock_path, strerror(errno));
		close(fd);
		return err;
	}
	/* Read-only commands are open to everyone; see privileged checks. */
	chmod(d->sock_path, 0666);

	d->listen_fd = fd;
	ev.data.fd = fd;
	return epoll_ctl(d->epfd, EPOLL_CTL_ADD, fd, &ev) ? -errno : 0;
}

static void client_close(struct hushd *d, struct ctl_client *c)
{
	struct ctl_client **pp;

	for (pp = &d->clients; *pp; pp = &(*pp)->next) {
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	}
	epoll_ctl(d->epfd, EPOLL_CTL_DEL, c->fd, NULL);
	close(c->fd);
	free(c);
	nr_clients--;
}

void ctl_accept(struct hushd *d)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP };
	struct ucred cred;
	socklen_t len = sizeof(cred);
	struct ctl_client *c;
	int fd;

	while ((fd = accept4(d->listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) >= 0) {
		if (nr_clients >= CTL_MAX_CLIENTS) {
			close(fd);
			continue;
		}
		c = calloc(1, sizeof(*c));
		if (!c) {
			close(fd);
			continue;
		}
		c->fd = fd;
		c->privileged = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) &&
				cred.uid == 0;
		ev.data.fd = fd;
		if (epoll_ctl(d->epfd, EPOLL_CTL_ADD, fd, &ev)) {
			close(fd);
			free(c);
			continue;
		}
		c->next = d->clients;
		d->clients = c;
		nr_clients++;
	}
}

static void send_all(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN) {
				/* Replies are small; a stuck reader just loses it. */
				usleep(1000);
				continue;
			}
			return;
		}
		buf += n;
		len -= n;
	}
}

static void handle_line(struct hushd *d, struct ctl_client *c, char *line)
{
	struct json_obj req;
	struct jw w;
	char err[128];

	jw_init(&w);
	if (json_parse(line, &req, err, sizeof(err))) {
		jw_obj_begin(&w, NULL);
		jw_str(&w, "status", "error");
		jw_str(&w, "message", err);
		jw_obj_end(&w);
	} else {
		hushd_handle(d, &req, c->privileged, &w);
		json_free(&req);
	}
	if (!w.oom && w.buf) {
		send_all(c->fd, w.buf, w.len);
		send_all(c->fd, "\n", 1);
	}
	jw_free(&w);
}

bool ctl_client_event(struct hushd *d, int fd, uint32_t events)
{
	struct ctl_client *c;
	char *nl;
	ssize_t n;

	for (c = d->clients; c && c->fd != fd; c = c->next)
		;
	if (!c)
		return false;

	for (;;) {
		n = recv(fd, c->buf + c->len, sizeof(c->buf) - 1 - c->len, 0);
		if (n > 0) {
			c->len += n;
			c->buf[c->len] = '\0';
			while ((nl = strchr(c->buf, '\n'))) {
				*nl = '\0';
				if (nl > c->buf)
					handle_line(d, c, c->buf);
				memmove(c->buf, nl + 1, c->len - (nl + 1 - c->buf));
				c->len -= nl + 1 - c->buf;
				c->buf[c->len] = '\0';
			}
			if (c->len >= sizeof(c->buf) - 1) {
				log_warn("control client sent an over-long request; dropping it");
				client_close(d, c);
				return true;
			}
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			break;
		/* EOF: a request without a trailing newline still gets an answer. */
		if (n == 0 && c->len)
			handle_line(d, c, c->buf);
		client_close(d, c);
		return true;
	}
	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
		client_close(d, c);
	return true;
}

void ctl_fini(struct hushd *d)
{
	while (d->clients)
		client_close(d, d->clients);
	if (d->listen_fd >= 0) {
		close(d->listen_fd);
		unlink(d->sock_path);
	}
	d->listen_fd = -1;
}
