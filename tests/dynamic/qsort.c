/*
 * qsort test
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
#include <string.h>
#include <stdio.h>

char *haystack[] = {
	"foo",
	"master",
	"needle",
	"noodle",
	"stack",
	"test",
	"a",
	"b",
	"bar",
};

static int cmpfn(const void *a, const void *b)
{
	const char * const * as = a, * const * bs = b;
	return strcmp(*as, *bs);
}

int main(int argc, char **argv)
{
	int nmemb = sizeof haystack/sizeof haystack[0];
	int i;

	qsort(haystack, nmemb, sizeof haystack[0], cmpfn);

	for (i = 1; i < nmemb; i++)
		if (0 <= strcmp(haystack[i - 1], haystack[i]))
			return 1;

	printf("OK\n");

	return 0;
}
