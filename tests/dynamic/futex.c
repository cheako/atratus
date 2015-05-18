/*
 * futex test
 *
 * Copyright (C)  2013 Mike McCormack
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
#include <stdint.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sys/time.h>
#include "ok.h"

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

int sys_futex(uint32_t *uaddr, int op, int val,
		const struct timespec *timeout, int *uaddr2, int val3);
__asm__ (
"\n"
"sys_futex:\n"
	"\tpushl %ebx\n"
	"\tmovl $240, %eax\n"
	"\tmovl 8(%esp), %ebx\n"
	"\tmovl 12(%esp), %ecx\n"
	"\tmovl 16(%esp), %edx\n"
	"\tmovl 20(%esp), %esi\n"
	"\tmovl 24(%esp), %edi\n"
	"\tint $0x80\n"
	"\tpopl %ebx\n"
	"\tret\n"
);

static int test_futex(void)
{
	uint32_t x = 0;
	int r;

	r = sys_futex(&x, FUTEX_WAIT, 2, NULL, 0, 0);
	OK(r == -EAGAIN);

	r = sys_futex(&x, FUTEX_WAIT, 1, NULL, 0, 0);
	OK(r == -EAGAIN);

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_futex())
		return 1;

	printf("OK\n");

	return 0;
}
