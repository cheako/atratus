/*
 * cat - Dependency free file concatenation program
 *
 * Copyright (C)  2011 - 2013 Mike McCormack
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

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#define MAP_FAILED ((void*)-1)

#define MAP_SHARED       1
#define MAP_PRIVATE      2
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20

#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4
#define PROT_NONE  0

#define O_RDONLY 0
#define O_RDWR 2

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

ssize_t read(int fd, char *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $3, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");
	return set_errno(r);
}

ssize_t write(int fd, const char *buffer, size_t length)
{
	int r;
	__asm__ __volatile__ (
		"\tmov $4, %%eax\n"
		"\tint $0x80\n"
	:"=a"(r): "b"(fd), "c"(buffer), "d"(length) : "memory");

	return set_errno(r);
}

int open(const char *filename, int flags)
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

void cat_fd(int fd)
{
	char buffer[0x100];
	int r;

	while (1)
	{
		r = read(fd, buffer, sizeof buffer);
		if (r <= 0)
			break;
		r = write(1, buffer, r);
		if (r <= 0)
			break;
	}
}

void cat(const char *path)
{
	int r, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		exit(1);

	cat_fd(fd);

	r = close(fd);
	if (r < 0)
		exit(2);
}

int main(int argc, char **argv)
{
	if (argc == 1)
		cat_fd(0);
	else
	{
		int i;
		for (i = 1; i < argc; i++)
			cat(argv[i]);
	}
	return 0;
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
