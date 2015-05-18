#include <string.h>
#include <stdio.h>

int test_strncmp(void)
{
	if (strncmp("a", "aa", 1) != 0)
		return 1;

	if (strncmp("a", "b", 0) != 0)
		return 1;

	if (strncmp("blah a", "blah b", 6) != -1)
		return 1;

	if (strncmp("AAA", "AAA", 3) != 0)
		return 1;

	return 0;
}

int test_strcmp(void)
{
	if (strcmp("a", "aa") != -1)
		return 1;

	if (strcmp("a", "b") != -1)
		return 1;

	if (strcmp("blah a", "blah b") != -1)
		return 1;

	if (strcmp("AAA", "AAA") != 0)
		return 1;

	if (strcmp("BAA", "AAA") != 1)
		return 1;

	if (strcmp("", "AAA") != -1)
		return 1;

	if (strcmp("AAA", "") != 1)
		return 1;

	if (strcmp("\255", "x") != 1)
		return 1;

	return 0;
}

int test_memcpy(void)
{
	const char *src = "hello";
	char dest[10];

	memset(dest, 'x', sizeof dest);
	memcpy(dest, src, 6);

	if (strcmp(dest, src))
		return 1;

	return 0;
}

int test_memmove(void)
{
	const char *src = "hello";
	char dest[10];

	memset(dest, 'x', sizeof dest);
	memmove(dest, src, 6);
	if (strcmp(dest, "hello"))
		return 1;

	memmove(dest + 1, dest, 6);
	if (strcmp(dest, "hhello"))
		return 1;

	memmove(dest, dest + 1, 6);
	if (strcmp(dest, "hello"))
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	if (test_strcmp())
		return 1;

	if (test_strncmp())
		return 1;

	if (test_memcpy())
		return 1;

	if (test_memmove())
		return 1;

	puts("OK");

	return 0;
}
