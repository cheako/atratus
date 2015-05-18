/*
 * stat64 - test the stat64 syscall
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

#include <sys/types.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

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

size_t strlen(const char *str)
{
	size_t n = 0;
	while (str[n])
		n++;
	return n;
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

static void write_int(unsigned int x)
{
	char ch[8];
	int i;
	for (i = 0; i < 8; i++)
	{
		ch[i] = (x>>((7-i)*4))&0x0f;
		if (ch[i] < 10)
			ch[i] += '0';
		else
			ch[i] += 55;
	}
	write(1, ch, 8);
}

struct stat64 {
	unsigned long long st_dev;
	int32_t __pad0;
	unsigned long st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned long st_uid;
	unsigned long st_gid;
	unsigned long long st_rdev;
	int32_t __pad1;
	long long st_size;
	unsigned long st_blksize;
	unsigned long long st_blocks;
	int st_atime;
	unsigned int st_atime_nsec;
	int st_mtime;
	unsigned int st_mtime_nsec;
	int st_ctime;
	unsigned int st_ctime_nsec;
	unsigned int __unused1;
	unsigned int __unused2;
};

int stat64(const char *path, struct stat64 *st)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(195), "b"(path), "c"(st) : "memory");

	return set_errno(r);
}

int main(int argc, char **argv)
{
	int i;
	unsigned char buf[0x100];
	struct stat64 *st = (void*) buf;

	for (i = 0; i < 0x100; i++)
		buf[i] = 'x';

	for (i = 1; i < argc; i++)
	{
		int r = stat64(argv[i], st);
		if (r != 0)
			return 1;
		if (buf[sizeof *st] != 'x')
			return 1;
		write_int(st->st_mode);
		write(1, " ", 1);
		write_int(st->st_uid);
		write(1, " ", 1);
		write_int(st->st_gid);
		write(1, " ", 1);
		write_int(st->st_size);
		write(1, " ", 1);
		write_int(st->st_atime);
		write(1, " ", 1);
		write_int(st->st_mtime);
		write(1, " ", 1);
		write_int(st->st_ctime);
		write(1, " ", 1);
		write(1, argv[i], strlen(argv[i]));
		write(1, "\n", 1);
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
