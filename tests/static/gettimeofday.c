/*
 * gettimeofday - show the gettimeofday() syscall output
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

#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

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

int write(int fd, const void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");

	return r;
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(78), "b"(tv), "c"(tz) : "memory");
	return r;
}

int itoa(unsigned int x, char *buf, int width)
{
	int i;
	for (i = width; i > 0; i--)
	{
		buf[i - 1] = '0' + (x % 10);
		x /= 10;
	}
	return width;
}

void _start(void)
{
	struct timeval tv;
	char buffer[18];

	if (0 == gettimeofday(&tv, NULL))
	{
		int n = itoa(tv.tv_sec, buffer, 10);
		buffer[n++] = ':';
		n += itoa(tv.tv_usec, buffer+n, 6);
		buffer[n++] = '\n';
		write(1, buffer, n);
	}

	exit(0);
}
