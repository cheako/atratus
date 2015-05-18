/*
 * dir - Basic directory listing
 *
 * Copyright (C)  2006-2012 Mike McCormack
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

int main(int argc, char **argv)
{
	unsigned char buf[0x1000];
	int fd;
	int r;
	int n = 0;

	fd = open(".", O_RDONLY);
	if (fd < 0)
	{
		char msg[] = "failed to open directory";
		write(2, msg, sizeof msg - 1);
		exit(1);
	}

	r = getdents(fd, (void*)buf, sizeof buf);

	while (n < r)
	{
		struct linux_dirent *de = (void*) &buf[n];

		write(1, de->d_name, strlen(de->d_name));
		write(1, "\n", 1);
		//printf("%s %08lx %d\n", de->d_name, de->d_off, de->d_reclen);
		if (de->d_reclen < sizeof *de)
			break;
		n += de->d_reclen;
	}

	close(fd);

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
