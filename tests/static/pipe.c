/*
 * simple pipe tests
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#define O_RDONLY 0

struct linux_dirent {
    long d_ino;
    off_t d_off;
    unsigned short d_reclen;
    char d_name[];
};

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

ssize_t read(int fd, void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $3, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");
	return set_errno(r);
}

ssize_t write(int fd, const void *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");

	return set_errno(r);
}

int open(const char *filename, int flags, ...)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(5), "b"(filename), "c"(flags) : "memory");

	return set_errno(r);
}

int close(int fd)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(6), "b"(fd) : "memory");

	return set_errno(r);
}

int pipe(int fds[2])
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(42), "b"(fds) : "memory");

	return set_errno(r);
}


static inline int getdents(int fd, struct linux_dirent *de, int len)
{
	int r;
	__asm__ __volatile__(
		"\tint $0x80\n"
		:"=a"(r)
		: "a"(141), "b"(fd), "c"(de), "d"(len)
		: "memory");
	return r;
}

size_t strlen(const char *str)
{
	size_t n = 0;
	while (str[n])
		n++;
	return n;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *left = s1, *right = s2;
	int r = 0;
	int i;

	for (i = 0; r == 0 && i < n; i++)
		r = left[n] - right[n];

	return r;
}

int main(int argc, char **argv)
{
	int fds[2];
	int r;
	char hw[] = "hello world";
	char buf[12];

	r = pipe(fds);
	if (r < 0)
	{
		char msg[] = "failed to create pipe";
		write(2, msg, sizeof msg - 1);
		exit(1);
	}

	r = write(fds[1], hw, sizeof hw - 1);
	if (r != sizeof hw - 1)
	{
		char msg[] = "write failed";
		write(2, msg, sizeof msg - 1);
		exit(1);
	}

	r = read(fds[0], buf, sizeof buf - 1);
	if (r != sizeof hw - 1)
	{
		char msg[] = "write failed";
		write(2, msg, sizeof msg - 1);
		exit(1);
	}

	if (!memcmp(buf, hw, sizeof hw - 1))
		r = 0;
	else
		r = 1;

	close(fds[1]);
	close(fds[0]);

	return r;
}

__asm__ (
	"\n"
".globl _start\n"
"_start:\n"
	"\tmovl 0(%esp), %eax\n"
	"\tlea 4(%esp), %ebx\n"
	"\tmov %ebx, %ecx\n"
"1:\n"
	"\tcmpl $0, 0(%ecx)\n"
	"\tlea 4(%ecx), %ecx\n"
	"\tjnz 1b\n"
	"\tpush %ecx\n"
	"\tmov %ecx, %edx\n"
"2:\n"
	"\tcmpl $0, 0(%ecx)\n"
	"\tlea 4(%ecx), %ecx\n"
	"\tjnz 2b\n"
	"\tpush %ecx\n"
	"\tpush %edx\n"
	"\tpush %ebx\n"
	"\tpush %eax\n"
	"\tcall main\n"
	"\tpush %eax\n"
	"\tcall exit\n"
);
