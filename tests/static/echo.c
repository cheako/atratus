/*
 * echo - a console test; read 10 characters and write them out again
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
#include <unistd.h>

void *__stack_chk_guard = 0;
void __stack_chk_fail_local(void) { return; }
void __stack_chk_fail(void) { return; }

static inline size_t sys_read(int fd, void *buffer, size_t len)
{
	int ret;
	__asm__ __volatile__(
		"pushl %%ebx; movl %2,%%ebx; int $0x80; popl %%ebx"
                          : "=a" (ret)
                          : "0" (SYS_read), "r" (fd), "c" (buffer), "d" (len)
                          : "memory" );
	return ret;
}

static inline size_t sys_write(int fd, const void *buffer, size_t len)
{
	int ret;
	__asm__ __volatile__(
		"pushl %%ebx; movl %2,%%ebx; int $0x80; popl %%ebx"
                          : "=a" (ret) : "0" (SYS_write), "r" (fd), "c" (buffer), "d" (len) );
	return ret;
}

static inline void sys_exit(int code)
{
	__asm__ __volatile__( "pushl %%ebx; movl %1,%%ebx; int $0x80; popl %%ebx"
			: : "a" (SYS_exit), "r" (code) );
}

void _start(void)
{
	char buf[10];
	int r;

	r = sys_read(0, buf, sizeof buf);
	if (r > 0)
	{
		sys_write(1, buf, sizeof r);
		sys_write(1, "\n", 1);
	}

	sys_exit(0);
}
