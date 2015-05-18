/*
 * stack - dump initial stack contents
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

static char buffer[0x2000];

static inline char tohex(unsigned int val)
{
	if (val <= 9)
		return val + '0';
	return val + 'A' - 10;
}

static inline void itoa(unsigned int val, char *buffer)
{
	int i = 8;
	while (i > 0)
	{
		i--;
		buffer[i] = tohex(val & 0x0f);
		val >>= 4;
	}
}

void _start(void *arg)
{
	unsigned char *x = (void*) &arg;
	char *p = buffer;
	int n = 0;
	int i;

	for (i = 0; i < 0x200; i++)
	{
		if (((int) &x[i] & 0xfff) == 0)
		{
			p[n++] = '\n';
			break;
		}
		if (i%16 == 0)
		{
			itoa((unsigned int)&x[i], &p[n]);
			n += 8;
			p[n++] = ' ';
		}
		p[n++] = tohex((x[i]>>4)&0x0f);
		p[n++] = tohex(x[i]&0x0f);
		p[n++] = ' ';
		if (i%16 == 15)
			p[n++] = '\n';
	}

	sys_write(1, buffer, n);
	sys_exit(0);
}
