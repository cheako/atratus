#include <unistd.h>
#include <stdio.h>

int test_getopt1(void)
{
	int r;
	char *t1[] = { "prog", "-n", NULL };

	if (optind != 1)
		return 0;

	r = getopt(2, t1, "nt:");
	if (r != 'n')
		return 0;

	if (optind != 2)
		return 0;

	r = getopt(2, t1, "nt:");
	if (r != -1)
		return 0;

	return 1;
}

int test_getopt2(void)
{
	int r;
	char *t2[] = { "prog", "-t", "foo", NULL };

	if (optind != 1)
		return 0;

	r = getopt(3, t2, "nt:");
	if (r != 't')
		return 0;

	if (optarg != t2[2])
		return 0;
	if (optind != 3)
		return 0;

	r = getopt(3, t2, "nt:");
	if (r != -1)
		return 0;

	return 1;
}

int test_getopt3(void)
{
	int r;
	char *t2[] = { "bb", "uname", "-m", NULL };

	optind = 0;
	r = getopt(3, t2, "snrvmpios");
	if (r != 'm')
		return 0;

	if (optind != 3)
		return 0;

	return 1;
}

int test_getopt4(void)
{
	int r;
	char *t2[] = { "bb", "wc", "README", NULL };

	optind = 0;
	r = getopt(3, t2, "l");
	if (r != -1)
		return 0;

	if (optind != 1)
		return 0;

	return 1;
}

int main(int argc, char **argv)
{
	if (optind != 1)
		return 1;
	if (optopt != '?')
		return 1;

	if (test_getopt1() != 1)
		return 1;

	optind = 1;
	optopt = '?';

	if (test_getopt2() != 1)
		return 1;

	optind = 1;
	optopt = '?';

	if (test_getopt3() != 1)
		return 1;

	if (test_getopt4() != 1)
		return 1;

	printf("ok\n");

	return 0;
}
