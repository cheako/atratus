/*
 * hw - dependency free hello world program
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

static inline size_t sys_write(int fd, const void *buffer, size_t len)
{
	int ret;
	__asm__ __volatile__(
		"int $0x80"
                          : "=a" (ret) : "a" (SYS_write), "b" (fd), "c" (buffer), "d" (len));
	return ret;
}

static inline void sys_exit(int code)
{
	__asm__ __volatile__(
		"int $0x80"
			: : "a" (SYS_exit), "b" (code) );
}

void _start(void)
{
	const char msg[] = "hello world\n";
	sys_write(1, msg, sizeof msg -1);
	sys_exit(0);
}
