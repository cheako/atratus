/*
 * pipe test
 *
 * Copyright (C)  2012 - 2013 Mike McCormack
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
#include <sys/select.h>
#include "ok.h"

int test_create_pipe(void)
{
	int fds[2] = {-1, -1};
	char buffer[10];
	fd_set fdset;
	struct timeval tv;
	int r;

	OK(0 == pipe(fds));

	OK(5 == write(fds[1], "hello", 5));
	OK(5 == read(fds[0], buffer, 5));
	OK(!memcmp(buffer, "hello", 5));

	OK(3 == write(fds[1], "bye", 3));
	OK(3 == read(fds[0], buffer, 3));
	OK(!memcmp(buffer, "bye", 3));

	OK(5 == write(fds[1], "hello", 5));
	OK(5 == read(fds[0], buffer, 5));
	OK(!memcmp(buffer, "hello", 5));

	OK(5 == write(fds[1], "hello", 5));
	OK(2 == read(fds[0], buffer, 2));
	OK(!memcmp(buffer, "he", 2));
	OK(3 == read(fds[0], buffer, 3));
	OK(!memcmp(buffer, "llo", 3));

	/* check fd is not pollable with no data in the pipe */
	FD_ZERO(&fdset);
	FD_SET(fds[0], &fdset);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	r = select(fds[0]+1, &fdset, NULL, NULL, &tv);
	OK(r == 0);
	OK(!FD_ISSET(fds[0], &fdset));

	/* check fd is pollable with data in the pipe */
	OK(1 == write(fds[1], "x", 1));
	FD_ZERO(&fdset);
	FD_SET(fds[0], &fdset);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	r = select(fds[0]+1, &fdset, NULL, NULL, &tv);
	OK(r == 1);
	OK(FD_ISSET(fds[0], &fdset));

	OK(0 == close(fds[0]));
	OK(0 == close(fds[1]));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_create_pipe())
		return 1;

	printf("OK\n");

	return 0;
}
