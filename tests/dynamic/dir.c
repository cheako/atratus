/*
 * Current working directory test
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "ok.h"

int test_getcwd(void)
{
	char buf[100], *d;

	OK(0 == chdir("/"));
	OK(buf == getcwd(buf, sizeof buf));
	OK(!strcmp(buf, "/"));

	d = getcwd(NULL, 0);
	OK(NULL != d);
	OK(!strcmp(d, "/"));
	free(d);

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_getcwd())
		return 1;

	puts("OK");

	return 0;
}
