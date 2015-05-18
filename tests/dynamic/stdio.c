/*
 * sprintf test
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

char *foo = NULL;

int test_sprintf(void)
{
	char out[0x100];
	sprintf(out, "%d", 0);
	OK(!strcmp("0", out));

	sprintf(out, "%d", 123);
	OK(!strcmp("123", out));

	sprintf(out, "%d", -1);
	OK(!strcmp("-1", out));

	sprintf(out, "test");
	OK(!strcmp("test", out));

	sprintf(out, "%s", "test");
	OK(!strcmp("test", out));

	sprintf(out, "%s %s", "test", "123");
	OK(!strcmp("test 123", out));

	sprintf(out, "%c", 'x');
	OK(!strcmp("x", out));

	sprintf(out, "%s", foo);
	OK(!strcmp("(null)", out));

	sprintf(out, "%x", 0x100);
	OK(!strcmp("100", out));

	sprintf(out, "%o", 0);
	OK(!strcmp("0", out));

	sprintf(out, "%o", 10);
	OK(!strcmp("12", out));

	sprintf(out, "%o", 64);
	OK(!strcmp("100", out));

	sprintf(out, "%4d", 64);
	OK(!strcmp("  64", out));

	sprintf(out, "%4d", 1000);
	OK(!strcmp("1000", out));

	sprintf(out, "%4d", 99999);
	OK(!strcmp("99999", out));

	sprintf(out, "%04o", 9);
	OK(!strcmp("0011", out));

	sprintf(out, "%04d", 9);
	OK(!strcmp("0009", out));

	sprintf(out, "%01x", 0x90);
	OK(!strcmp("90", out));

	sprintf(out, "%09x", 0x90);
	OK(!strcmp("000000090", out));

	sprintf(out, "%4x", 0x123);
	OK(!strcmp(" 123", out));

	sprintf(out, "%u", ~0);
	OK(!strcmp("4294967295", out));

	sprintf(out, "%04u", 0);
	OK(!strcmp("0000", out));

	sprintf(out, "%llu %llu", 1LL, 2LL);
	OK(!strcmp("1 2", out));

	sprintf(out, "fn(): %c\n", 'x');
	OK(!strcmp("fn(): x\n", out));

	sprintf(out, "%%x");
	OK(!strcmp("%x", out));

	sprintf(out, "%*x", 4, 0x123);
	OK(!strcmp(" 123", out));

	sprintf(out, "%*s", 4, "x");
	OK(!strcmp("   x", out));

	sprintf(out, "%.1s", "xyz");
	OK(!strcmp("x", out));

	sprintf(out, "%.*s", 2, "xyz");
	OK(!strcmp("xy", out));

	sprintf(out, "%-s", "xyz");
	OK(!strcmp("xyz", out));

	sprintf(out, "%-3s", "xyz");
	OK(!strcmp("xyz", out));

	sprintf(out, "%-4s", "xyz");
	OK(!strcmp("xyz ", out));

	sprintf(out, "%-4d", 1);
	OK(!strcmp("1   ", out));

	sprintf(out, "%zd", 1);
	OK(!strcmp("1", out));

	return 1;
}

int test_asprintf(void)
{
	char *out = NULL;
	int r;

	r = asprintf(&out, "%d", 0);
	OK(r == 1);
	OK(!strcmp("0", out));
	free(out);

	r = asprintf(&out, "%c%c%cbar", 'f', 'o', 'o');
	OK(r == 6);
	OK(!strcmp("foobar", out));
	free(out);

	return 1;
}

int test_snprintf(void)
{
	char out[0x100];
	int n;

	n = snprintf(out, 1, "%d", 100);
	OK(!strcmp("", out));
	OK(n == 3);

	n = snprintf(out, 2, "%d", 100);
	OK(!strcmp("1", out));
	OK(n == 3);

	n = snprintf(out, 3, "%d", 100);
	OK(!strcmp("10", out));
	OK(n == 3);

	n = snprintf(out, 4, "%d", 100);
	OK(!strcmp("100", out));
	OK(n == 3);

	out[0] = 0;
	n = snprintf(out, 0, "%d", 100);
	OK(out[0] == 0);
	OK(n == 3);

	return 1;
}

int test_sscanf(void)
{
	int val = 0, val2 = 0;
	char ch = 0;

	OK(1 == sscanf("1", "%d", &val));
	OK(val == 1);

	OK(2 == sscanf("32", "%1d%1d", &val, &val2));
	OK(val == 3);
	OK(val2 == 2);

	OK(2 == sscanf("-32", "%2d%1d", &val, &val2));
	OK(val == -3);
	OK(val2 == 2);

	OK(1 == sscanf("-32", "%u", &val));
	OK(val == -32);

	OK(1 == sscanf("32", "%u", &val));
	OK(val == 32);

	OK(1 == sscanf("64", "%2u", &val));
	OK(val == 64);

	OK(1 == sscanf("6", "%c", &ch));
	OK(ch == '6');

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_sprintf())
		return 1;

	if (!test_asprintf())
		return 1;

	if (!test_snprintf())
		return 1;

	if (!test_sscanf())
		return 1;

	printf("OK\n");

	return 0;
}
