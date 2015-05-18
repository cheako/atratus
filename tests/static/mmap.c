/*
 * mmap - simple mmap tests
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
#include <sys/mman.h>
#include <unistd.h>

void *__stack_chk_guard = 0;
void __stack_chk_fail_local(void) { return; }
void __stack_chk_fail(void) { return; }

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


ssize_t write(int fd, const void *buffer, size_t len)
{
	int r;
	__asm__ __volatile__(
		"int $0x80"
	: "=a" (r)
	: "a" (SYS_write), "b" (fd), "c" (buffer), "d" (len)
	: "memory");
	return set_errno(r);
}

void exit(int code)
{
	while (1)
	{
		__asm__ __volatile__(
			"int $0x80"
		: : "a" (SYS_exit), "b" (code)
		: "memory" );
	}
}

void* mmap(void *start, size_t len, int prot, int flags, int fd, off_t offset)
{
	int r;

	__asm__ __volatile__(
		"\tpush %%ebp\n"
		"\tmov %%eax, %%ebp\n"
		"\tmov $192, %%eax\n"
		"\tint $0x80\n"
		"\tpop %%ebp\n"
		: "=a"(r) : "a" (offset), "b" (start),
                 "c"(len), "d"(prot), "S"(flags),
		 "D"(fd) : "memory"
	);

	if ((r & 0xfffff000) == 0xfffff000)
	{
		errno = - (int) r;
		return MAP_FAILED;
	}

	return (void*) r;
}

int munmap(void *address, size_t length)
{
	int r;
	__asm__ __volatile__(
		"int $0x80"
	: "=a" (r)
	: "a" (SYS_munmap), "b" (address), "c" (length)
	: "memory");
	return set_errno(r);
}

void _start(void)
{
	const char msg[] = "mmap ok\n";
	void *p, *addr;

	p = mmap(NULL, 0x2000, PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1, 0);
	if (p == MAP_FAILED)
	{
		const char fail[] = "map failed (1)\n";
		write(2, fail, sizeof fail - 1);
		exit(1);
	}

	addr = mmap(p, 0x1000, PROT_NONE,
		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
		-1, 0);
	if (addr == MAP_FAILED)
	{
		const char fail[] = "map failed (2)\n";
		write(2, fail, sizeof fail - 1);
		exit(1);
	}

	munmap(p, 0x1000);

	write(1, msg, sizeof msg -1);

	exit(0);
}
