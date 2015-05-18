#include <unistd.h>
#include <stdio.h>
#include <getopt.h>

int test_getopt_long1(void)
{
	int r;
	char *t1[] = { "prog", "--yes", "-n", NULL };
	struct option lo1[] = {
		{ "yes", 0, 0, 'y' },
		{ 0, 0, 0, 0 },
	};

	if (optind != 1)
		return 0;

	r = getopt_long(3, t1, "nt:", lo1, NULL);
	if (r != 'y')
		return 0;

	if (optind != 2)
		return 0;

	r = getopt_long(3, t1, "nt:", lo1, NULL);
	if (r != 'n')
		return 0;

	if (optind != 3)
		return 0;

	r = getopt_long(3, t1, "nt:", lo1, NULL);
	if (r != -1)
		return 0;

	return 1;
}

int test_getopt_long2(void)
{
	int r;
	char *t2[] = { "prog", "--bar", "--foo", "xyz", NULL };
	int var = 0;
	struct option lo2[] = {
		{ "bar", 0, 0, 'y' },
		{ "foo", 1, &var, 'x' },
		{ 0, 0, 0, 0 },
	};

	if (optind != 1)
		return 0;

	r = getopt_long(4, t2, "", lo2, NULL);
	if (r != 'y')
		return 0;
	if (optind != 2)
		return 0;

	r = getopt_long(4, t2, "", lo2, NULL);
	if (r != 0)
		return 0;
	if (optopt != 0)
		return 0;
	if (optarg != t2[3])
		return 0;
	if (optind != 4)
		return 0;

	r = getopt_long(4, t2, "", lo2, NULL);
	if (r != -1)
		return 0;

	return 1;
}

int main(int argc, char **argv)
{
	if (optind != 1)
		return 1;
	if (optopt != '?')
		return 1;

	if (test_getopt_long1() != 1)
		return 1;

	optind = 1;
	optopt = '?';

	if (test_getopt_long2() != 1)
		return 1;

	printf("ok\n");

	return 0;
}
