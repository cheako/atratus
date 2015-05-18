#include <stdlib.h>
#include <stdio.h>

int test_strtoul(void)
{
	char *p = NULL;
	if (0 != strtoul("", &p, 10))
		return 1;
	if (*p != 0)
		return 1;
	if (1 != strtoul("1", NULL, 10))
		return 1;
	if (10 != strtoul("10", NULL, 10))
		return 1;
	if (8765432 != strtoul("8765432", NULL, 10))
		return 1;
	if (1 != strtoul("+1", NULL, 10))
		return 1;
	if (-1 != strtoul("-1", NULL, 10))
		return 1;
	if (0x10 != strtoul("0x10", NULL, 16))
		return 1;
	if (123 != strtoul("123x", &p, 10))
		return 1;
	if (*p != 'x')
		return 1;
	return 0;
}

int test_strtoll(void)
{
	if (0 != strtoll("", NULL, 10))
		return 1;
	if (1 != strtoll(" 1", NULL, 10))
		return 1;
	if (1 != strtoll("\t 1", NULL, 10))
		return 1;
	if (100000000000 != strtoll("100000000000", NULL, 10))
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	if (test_strtoul())
		return 1;

	if (test_strtoll())
		return 1;

	printf("ok\n");
	return 0;
}
