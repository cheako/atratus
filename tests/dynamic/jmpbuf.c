/*
 * setjmp/longjmp test
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
#include <setjmp.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	jmp_buf env;
	int r;
	volatile int x = 0x67895432;

	r = setjmp(env);
	if (r)
	{
		if (x != 0x67895432)
			exit(1);
		if (r == 2)
			goto again;
		goto finish;
	}

	longjmp(env, 2);

again:
	longjmp(env, 0);

	printf("fail\n");

	exit(1);
finish:
	printf("ok\n");
	exit(0);
}
