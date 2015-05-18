/*
 * time functions test
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
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "ok.h"

int test_mktime(void)
{
	struct tm tm =
 	{
		.tm_year = 112,
		.tm_mon = 11,
		.tm_mday = 16,
		.tm_hour = 21,
		.tm_min = 42,
		.tm_sec = 1,
		.tm_wday = 10,
		.tm_yday = 10,
	};
	struct tm tm2;
	time_t t;

	t = mktime(&tm);
	OK(t == 1355694121);
	OK(tm.tm_wday == 0);
	OK(tm.tm_yday == 350);

	OK(&tm2 == gmtime_r(&t, &tm2));

	OK(tm2.tm_year == 112);
	OK(tm2.tm_mon == 11);
	OK(tm2.tm_mday == 16);
	OK(tm2.tm_hour == 21);

	tm.tm_year = 0;
	OK(-1 == mktime(&tm));

	tm.tm_year = 2012;
	OK(-1 == mktime(&tm));

	return 1;
}

int main(int argc, char **argv)
{
	setenv("TZ", "", 1);
	tzset();

	if (!test_mktime())
		return 1;

	printf("OK\n");

	return 0;
}
