/*
 * Environment test
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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ok.h"

int test_setenv(void)
{
	unsetenv("X");
	OK(NULL == getenv("X"));

	OK(0 == setenv("X", "foo", 0));
	OK(!strcmp(getenv("X"), "foo"));

	OK(0 == setenv("X", "bar", 0));
	OK(!strcmp(getenv("X"), "foo"));

	OK(0 == setenv("X", "bar", 1));
	OK(!strcmp(getenv("X"), "bar"));

	OK(0 == unsetenv("X"));
	OK(NULL == getenv("X"));

	OK(0 == setenv("X", "bar", 1));
	OK(!strcmp(getenv("X"), "bar"));

	OK(0 == clearenv());
	OK(NULL == getenv("X"));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_setenv())
		return 1;

	printf("OK\n");

	return 0;
}
