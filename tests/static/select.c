/*
 * select - test select
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

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

typedef unsigned long size_t;

#define NULL ((void*)0)

struct timeval
{
	long tv_sec;
	long tv_usec;
};

struct fdset
{
	unsigned long fds_bits[1024/32];
};

struct pollfd
{
	int fd;
	short events;
	short revents;
};

void __stack_chk_fail(void)
{
}

/*
 * minwgcc and gcc have different definitions of __thread
 * errno should be per thread,
 * leave as global until we can load an ELF binary
 */
int errno;

static inline int set_errno(int r)
{
	if ((r & 0xfffff000) == 0xfffff000)
	{
		errno = -r;
		r = -1;
	}
	return r;
}

void exit(int status)
{
	while (1)
	{
		__asm__ __volatile__ (
			"\tmov $1, %%eax\n"
			"\tint $0x80\n"
		:: "b"(status) : "memory");
	}
}

int read(int fd, char *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $3, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");
	return set_errno(r);
}

int write(int fd, const char *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");

	return set_errno(r);
}

int sys_select(void *args)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	: "=a"(r)
	: "a"(82), "b"(args)
	: "memory");

	return set_errno(r);
}

int select(int nfds, struct fdset *readfds, struct fdset *writefds,
		struct fdset *exceptfds, struct timeval *timeout)
{
	struct {
		int nfds;
		struct fdset *rfds;
		struct fdset *wfds;
		struct fdset *efds;
		struct timeval *tv;
	} args = { nfds, readfds, writefds, exceptfds, timeout };
	return sys_select(&args);
}

static inline char tohex(unsigned int val)
{
	if (val <= 9)
		return val + '0';
	return val + 'A' - 10;
}

static inline void itox(unsigned int val, char *buffer)
{
	int i = 8;
	while (i > 0)
	{
		i--;
		buffer[i] = tohex(val & 0x0f);
		val >>= 4;
	}
}

void *memset(void *s, int c, size_t n)
{
	unsigned char *uc = s;
	size_t i;

	for (i = 0; i < n; i++)
		uc[i] = c;
	return s;
}

void _start(void)
{
	int r;
	struct fdset rfds, wfds, errfds;
	struct timeval tv = {0, 0};

	memset(&rfds, 0, sizeof rfds);
	memset(&wfds, 0, sizeof wfds);
	memset(&errfds, 0, sizeof errfds);

	if (0)
	{
		/* this hangs indefinitely */
		r = select(0, 0, 0, 0, 0);
		if (r != -1 || errno != 14)
			exit(1);
	}

	r = select(0, 0, 0, 0, &tv);
	if (r != 0)
		exit(1);

	r = select(0, &rfds, &wfds, &errfds, &tv);
	if (r != 0)
		exit(1);

	write(1, "OK\n", 3);
	exit(0);
}
