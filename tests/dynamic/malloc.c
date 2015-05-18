/*
 * Heap test
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
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	char *p, *p2;
	int i;

	p = malloc(0);
	free(p);

	p = malloc(100);
	memset(p, 0, 100);
	free(p);

	p = malloc(10000);
	memset(p, 0, 10000);
	free(p);

	p = malloc(1000);
	strcpy(p, "hello");
	p[999] = 'x';
	p2 = malloc(1000);
	p = realloc(p, 10000);

	if (strcmp(p, "hello"))
		return 1;
	if (p[999] != 'x')
		return 1;
	free(p);
	free(p2);

	free(NULL);

	p = malloc(1);
	p2 = malloc(10);
	for (i = 2; i < 1000; i++)
	{
		p = realloc(p, i);
		p2 = realloc(p2, i * 2);
	}

	free(p);

	p = strdup("hello");
	if (strcmp("hello", p))
		return 1;

	puts("ok");
	return 0;
}
