/*
 * dir - Basic directory listing
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

struct linux_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
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


static inline int getdents64(int fd, struct linux_dirent64 *de, int len)
{
	int r;
	__asm__ __volatile__(
		"\tint $0x80\n"
		:"=a"(r)
		: "a"(220), "b"(fd), "c"(de), "d"(len)
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
			ch[i] += ('A' - 10);
	}
	write(1, ch, 8);
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

	r = getdents64(fd, (void*)buf, sizeof buf);

#if 1
	while (n < r)
	{
		struct linux_dirent64 *de = (void*) &buf[n];

		write_int(de->d_reclen);
		write(1, " ", 1);
		write_int(de->d_off);
		write(1, " ", 1);
		write_int(de->d_ino);
		write(1, " ", 1);
		char t = de->d_type;
		switch (t)
		{
		case 10: /* link */
			write(1, "l", 1);
			break;
		case 8:	/* file */
			write(1, " ", 1);
			break;
		case 4: /* dir */
			write(1, "d", 1);
			break;
		default:
			write_int(t);
		}
		write(1, " ", 1);
		write(1, de->d_name, strlen(de->d_name));
		write(1, "\n", 1);
		//printf("%s %08lx %d\n", de->d_name, de->d_off, de->d_reclen);
		if (de->d_reclen < sizeof *de)
			break;
		n += de->d_reclen;
	}
#else
	for (n = 0; n < r; n++)
	{
		unsigned char x = buf[n];
#define HEX(b) (((b) < 10 ) ? ((b) + '0') : ((b) + 'A' - 10))
		char ch[3] = { HEX(x >> 4), HEX(x&0x0f),
				(n + 1) % 16 ? ' ' : '\n' };
		write(1, ch, 3);
	}
#endif

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
