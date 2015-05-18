/*
 * stat - test the stat syscall
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

struct stat {
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned long st_rdev;
	unsigned long st_size;
	unsigned long st_blksize;
	unsigned long st_blocks;
	unsigned long st_atime;
	unsigned long st_atime_nsec;
	unsigned long st_mtime;
	unsigned long st_mtime_nsec;
	unsigned long st_ctime;
	unsigned long st_ctime_nsec;
	unsigned long __unused1;
	unsigned long __unused2;
};

int stat(const char *path, struct stat *st)
{
	int r;
	__asm__ __volatile__ (
		"\tint $0x80\n"
	:"=a"(r): "a"(106), "b"(path), "c"(st) : "memory");

	return set_errno(r);
}

int main(int argc, char **argv)
{
	int i;
	struct stat st;

	for (i = 1; i < argc; i++)
	{
		stat(argv[i], &st);
		write_int(st.st_mode);
		write(1, " ", 1);
		write_int(st.st_size);
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
