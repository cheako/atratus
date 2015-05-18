/*
 * pipe test
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

#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "ok.h"

int test_create_pipe(void)
{
	int fds[2] = {-1, -1};

	OK(0 == pipe(fds));
	OK(0 == close(fds[0]));
	OK(0 == close(fds[1]));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_create_pipe())
		return 1;

	printf("OK\n");

	return 0;
}
