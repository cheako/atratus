/*
 * stdlib functions test
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

#include <stdlib.h>
#include <stdio.h>
#include "ok.h"

int test_strtoul(void)
{
	char *p = NULL;
	OK(0 == strtoul("", &p, 10));
	OK(*p == 0);
	OK(1 == strtoul("1", NULL, 10));
	OK(10 == strtoul("10", NULL, 10));
	OK(8765432 == strtoul("8765432", NULL, 10));
	OK(1 == strtoul("+1", NULL, 10));
	OK(-1 == strtoul("-1", NULL, 10));
	OK(0x10 == strtoul("0x10", NULL, 16));
	OK(123 == strtoul("123x", &p, 10));
	OK(*p == 'x');
	OK(127 == strtoul("0x7f", &p, 16));

	return 1;
}

int test_strtoll(void)
{
	OK(0 == strtoll("", NULL, 10));
	OK(1 == strtoll(" 1", NULL, 10));
	OK(1 == strtoll("\t 1", NULL, 10));
	OK(100000000000 == strtoll("100000000000", NULL, 10));

	return 1;
}

int test_atoi(void)
{
	OK(0 == atoi(""));
	OK(0 == atoi("0"));
	OK(9 == atoi("9"));
	OK(42 == atoi("42"));
	OK(-42 == atoi("-42"));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_strtoul())
		return 1;

	if (!test_strtoll())
		return 1;

	if (!test_atoi())
		return 1;

	printf("OK\n");
	return 0;
}
