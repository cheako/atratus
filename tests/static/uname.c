/*
 * uname - Dump the system name
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

#include <sys/syscall.h>
#include <unistd.h>

void *__stack_chk_guard = 0;
void __stack_chk_fail_local(void) { return; }
void __stack_chk_fail(void) { return; }

size_t sys_write(int fd, const void *buffer, size_t len)
{
	int ret;
	__asm__ __volatile__(
		"int $0x80"
                          : "=a" (ret) : "a" (SYS_write), "b" (fd), "c" (buffer), "d" (len));
	return ret;
}

void sys_exit(int code)
{
	__asm__ __volatile__(
		"int $0x80"
			: : "a" (SYS_exit), "b" (code) );
}

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

int sys_uname(struct new_utsname *un)
{
	int ret;
	__asm__ __volatile__(
		"int $0x80"
			: "=a"(ret) : "a" (SYS_uname), "b" (un) );
	return ret;
}

static int _strlen(const char *x)
{
	int n = 0;
	while (x[n])
		n++;
	return n;
}

void print(const char *string)
{
	sys_write(1, string, _strlen(string));
}

void *memset(void *p, int c, size_t n)
{
	unsigned char *x = p;
	int i;

	for (i = 0; i < n; i++)
		x[n] = c;
	return p;
}

void _start(void)
{
	struct new_utsname un;
	int r;

	memset(&un, 0, sizeof un);
	r = sys_uname(&un);
	if (!r)
	{
		print("sysname:    ");
		print(un.sysname);
		print("\n");
		print("nodename:   ");
		print(un.nodename);
		print("\n");
		print("release:    ");
		print(un.release);
		print("\n");
		print("version:    ");
		print(un.version);
		print("\n");
		print("machine:    ");
		print(un.machine);
		print("\n");
		print("domainname: ");
		print(un.domainname);
		print("\n");
	}
	sys_exit(0);
}
