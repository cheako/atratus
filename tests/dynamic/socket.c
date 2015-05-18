/*
 * socket test
 *
 * Copyright (C)  2013 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include "ok.h"

int test_socket(void)
{
	struct sockaddr_in sin;
	int s, ss, c, r, opt;
	struct sockaddr_in sa;
	struct sockaddr_in name;
	socklen_t sl;
	struct pollfd pfd[2];
	char buffer[16];

	s = socket(AF_INET, SOCK_STREAM, 0);
	OK(s > 0);

	c = socket(AF_INET, SOCK_STREAM, 0);
	OK(c > 0);

	opt = 1;
	r = setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			&opt, sizeof opt);
	OK(r == 0);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(12345);
	r = bind(s, (void*) &sin, sizeof sin);
	OK(r == 0);

	r = listen(s, 1);
	OK(r == 0);

	r = fcntl(s, F_SETFL, O_NONBLOCK);
	OK(r == 0);

	sl = sizeof sa;
	r = accept(s, &sa, &sl);
	OK(r == -1 && errno == EAGAIN);

	r = connect(c, &sin, sizeof sin);
	OK(r == 0);

	sl = sizeof sa;
	r = getpeername(c, &name, &sl);
	OK(r == 0);
	OK(name.sin_family == AF_INET);
	OK(name.sin_port == sin.sin_port);
	OK(name.sin_addr.s_addr == sin.sin_addr.s_addr);

	pfd[0].fd = s;
	pfd[0].events = POLLIN | POLLOUT;
	pfd[0].revents = 0;
	pfd[1].fd = c;
	pfd[1].events = POLLIN | POLLOUT;
	pfd[1].revents = 0;
	r = poll(pfd, 2, 0);
	OK(r == 2);
	OK(pfd[0].revents == POLLIN);
	OK(pfd[1].revents == POLLOUT);

	sl = sizeof sa;
	ss = accept(s, &sa, &sl);
	OK(ss > 0);
	OK(sl == sizeof sa);
	OK(sin.sin_addr.s_addr == sa.sin_addr.s_addr);

	/* write one byte, read one byte */
	OK(1 == write(ss, "x", 1));
	buffer[0] = ' ';
	OK(1 == read(c, buffer, 1));
	OK(buffer[0] == 'x');

	/* write one, read many */
	OK(1 == write(ss, "y", 1));
	buffer[0] = ' ';
	OK(1 == read(c, buffer, sizeof buffer));
	OK(buffer[0] == 'y');

	OK(0 == shutdown(ss, SHUT_WR));
	OK(0 == close(ss));

	pfd[0].fd = c;
	pfd[0].events = POLLIN | POLLHUP;
	pfd[0].revents = 0;
	r = poll(pfd, 1, 0);
	OK(r == 1);
	OK(pfd[0].revents == POLLIN);

	OK(0 == shutdown(c, SHUT_WR));
	OK(0 == close(c));

	OK(0 == close(s));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_socket())
		return 1;

	printf("OK\n");

	return 0;
}
