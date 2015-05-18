/*
 * getopt test
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

#include <unistd.h>
#include <stdio.h>
#include "ok.h"

int test_getopt1(void)
{
	int r;
	char *t1[] = { "prog", "-n", NULL };

	OK(optind == 1);

	r = getopt(2, t1, "nt:");
	OK(r == 'n');
	OK(optind == 2);
	OK(optarg == NULL);

	r = getopt(2, t1, "nt:");
	OK(r == -1);

	return 1;
}

int test_getopt2(void)
{
	int r;
	char *t2[] = { "prog", "-t", "foo", NULL };

	OK(optind == 1);

	r = getopt(3, t2, "nt:");
	OK(r == 't');

	OK(optarg == t2[2]);
	OK(optind == 3);

	r = getopt(3, t2, "nt:");
	OK(r == -1);
	OK(optarg == NULL);

	return 1;
}

int test_getopt3(void)
{
	int r;
	char *t2[] = { "bb", "uname", "-m", NULL };

	optind = 0;
	r = getopt(3, t2, "snrvmpios");
	OK(r == 'm');
	OK(optind == 3);
	OK(optarg == NULL);

	return 1;
}

int test_getopt4(void)
{
	int r;
	char *t2[] = { "bb", "wc", "README", NULL };

	optind = 0;
	r = getopt(3, t2, "l");
	OK(r == -1);
	OK(optind == 1);
	OK(optarg == NULL);

	return 1;
}

int test_getopt5(void)
{
	int r;
	char *t5[] = { "tail", "-n", "10", "README", "foo", NULL };

	optind = 0;
	r = getopt(5, t5, "n:");
	OK(r == 'n');

	OK(optarg == t5[2]);
	OK(optind == 3);

	r = getopt(5, t5, "n:");
	OK(r == -1);
	OK(optind == 3);
	OK(optarg == NULL);

	r = getopt(5, t5, "n:");
	OK(r == -1);
	OK(optind == 3);
	OK(optarg == NULL);

	return 1;
}

int test_getopt6(void)
{
	int r;
	char *t2[] = { "a", "b", "c", "d", "e", NULL };

	optind = 0;
	r = getopt(5, t2, "l");
	OK(r == -1);
	OK(optind == 1);
	OK(optarg == NULL);

	optind = 1;
	r = getopt(5, t2, "l");
	OK(r == -1);
	OK(optind == 1);
	OK(optarg == NULL);

	optind = 2;
	r = getopt(5, t2, "l");
	OK(r == -1);
	OK(optind == 1);
	OK(optarg == NULL);

	return 1;
}

int test_getopt7(void)
{
	int r;
	char *a1 = "tail";
	char *a2 = "README";
	char *a3 = "foo";
	char *a4 = "-n";
	char *a5 = "10";
	char *t7[] = { a1, a2, a3, a4, a5, NULL };
	int ac = 5;

	optind = 0;
	r = getopt(ac, t7, "n:");
	OK(r == 'n');

	OK(optarg == a5);
	OK(optind == 5);

#if 0
	r = getopt(ac, t7, "n:");
	OK(r == -1);
	OK(optind == 3);
	OK(optarg == NULL);

	r = getopt(ac, t7, "n:");
	OK(r == -1);
	OK(optind == 3);
	OK(optarg == NULL);
#endif

	return 1;
}

int unit_main(void)
{
	/* test initial values */
	OK(optind == 1);
	OK(optopt == '?');
	OK(opterr == 1);

	opterr = 0;

	OK(test_getopt1() == 1);

	optind = 1;
	optopt = '?';

	OK(test_getopt2() == 1);

	optind = 1;
	optopt = '?';

	OK(test_getopt3() == 1);

	optind = 1;
	optopt = '?';

	OK(test_getopt4() == 1);

	optind = 1;
	optopt = '?';

	OK(test_getopt5() == 1);

	OK(test_getopt6() == 1);

	OK(test_getopt7() == 1);

	return 0;
}

int main(int argc, char **argv)
{
	if (unit_main())
		return 1;
	printf("OK\n");
	return 0;
}
