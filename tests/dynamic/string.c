#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>

#define OK(expr) \
	do { \
		if (!(expr)) \
		{ \
			printf("expression '%s' untrue at %d\n", \
				 #expr, __LINE__); \
			return 0; \
		} \
	} while (0)

int test_strlen(void)
{
	OK(strlen("") == 0);
	OK(strlen("a") == 1);
	OK(strlen("long string") == 11);
	return 1;
}

int test_strncmp(void)
{
	OK(strncmp("a", "aa", 1) == 0);
	OK(strncmp("a", "b", 0) == 0);
	OK(strncmp("blah a", "blah b", 6) == -1);
	OK(strncmp("AAA", "AAA", 3) == 0);

	return 1;
}

int test_strcmp(void)
{
	OK(strcmp("a", "aa") == -1);
	OK(strcmp("a", "b") == -1);
	OK(strcmp("blah a", "blah b") == -1);
	OK(strcmp("AAA", "AAA") == 0);
	OK(strcmp("BAA", "AAA") == 1);
	OK(strcmp("", "AAA") == -1);
	OK(strcmp("AAA", "") == 1);
	OK(strcmp("\255", "x") == 1);

	return 1;
}

int test_memcpy(void)
{
	const char *src = "hello";
	char dest[10];

	memset(dest, 'x', sizeof dest);
	OK(dest == memcpy(dest, src, 6));
	OK(strcmp(dest, src) == 0);

	return 1;
}

int test_mempcpy(void)
{
	const char *src = "hello";
	char dest[10];

	memset(dest, 'x', sizeof dest);
	OK(&dest[6] == mempcpy(dest, src, 6));
	OK(strcmp(dest, src) == 0);

	return 1;
}

int test_memmove(void)
{
	const char *src = "hello";
	char dest[10];

	memset(dest, 'x', sizeof dest);
	memmove(dest, src, 6);
	OK(strcmp(dest, "hello") == 0);
	memmove(dest + 1, dest, 6);
	OK(strcmp(dest, "hhello") == 0);
	memmove(dest, dest + 1, 6);
	OK(strcmp(dest, "hello") == 0);

	return 1;
}

int test_strcpy(void)
{
	char dest[10];

	OK(dest == strcpy(dest, "hello"));
	OK(!strcmp(dest, "hello"));

	OK(dest == strcpy(dest, ""));
	OK(dest[0] == 0);

	return 1;
}

int test_strncpy(void)
{
	char dest[10];

	dest[5] = 'x';
	dest[6] = 'x';
	dest[7] = 0;
	OK(dest == strncpy(dest, "hello", 5));
	OK(!strcmp(dest, "helloxx"));

	OK(dest == strncpy(dest, "hello", 6));
	OK(!strcmp(dest, "hello"));
	OK(dest[6] == 'x');

	OK(dest == strncpy(dest, "hello", 7));
	OK(!strcmp(dest, "hello"));
	OK(dest[6] == 0);

	OK(dest == strncpy(dest, "", 0));
	OK(!strcmp(dest, "hello"));

	OK(dest == strncpy(dest, "", 1));
	OK(!strcmp(dest, ""));

	return 1;
}

int test_strspn(void)
{
	OK(strspn("", "") == 0);
	OK(strspn("xyz", "") == 0);
	OK(strspn("xyz", "z") == 0);
	OK(strspn("xyzabc", "zxlyz") == 3);
	OK(strspn("12344xyz", "0123456789") == 5);

	return 1;
}

int test_strcat_chk(void)
{
	char dest[32];

	dest[0] = 0;
	OK(dest == __strcat_chk(dest, "xyz", sizeof dest));
	OK(strcmp(dest, "xyz") == 0);
	OK(dest == __strcat_chk(dest, "xyz", sizeof dest));
	OK(strcmp(dest, "xyzxyz") == 0);

	return 1;
}

int test_memchr(void)
{
	char data[] = "xyz\0abc";
	OK(&data[2] == memchr(data, 'z', sizeof data));
	OK(&data[3] == memchr(data, '\0', sizeof data));
	OK(NULL == memchr(data, 'd', sizeof data));

	return 1;
}

int test_memrchr(void)
{
	char data[] = "xyz\0abc";

	OK(&data[2] == memrchr(data, 'z', sizeof data));
	OK(&data[7] == memrchr(data, '\0', sizeof data));
	OK(NULL == memrchr(data, 'd', sizeof data));

	return 1;
}

int test_strchr(void)
{
	char data[] = "xyz\0abc";

	OK(&data[2] == strchr(data, 'z'));
	OK(&data[3] == strchr(data, '\0'));
	OK(NULL == strchr(data, 'd'));

	return 1;
}

int test_strchrnul(void)
{
	char data[] = "xyz";

	OK(&data[2] == strchrnul(data, 'z'));
	OK(&data[3] == strchrnul(data, '\0'));
	OK(&data[3] == strchrnul(data, 'd'));

	return 1;
}

int test_strrchr(void)
{
	char data[] = "xyyyz";

	OK(&data[4] == strrchr(data, 'z'));
	OK(&data[4] == strrchr(data, 'z'));

	/* gcc replaces these with strchr */
	OK(&data[5] == strrchr(data, 0));
	OK(&data[5] == strrchr(data, '\0'));

	OK(NULL == strrchr(data, 'd'));
	OK(&data[3] == strrchr(data, 'y'));
	OK(&data[0] == strrchr(data, 'x'));

	return 1;
}

int test_strncat_chk(void)
{
	char dest[32];

	dest[0] = 0;
	OK(dest == __strncat_chk(dest, "xyz", 4, sizeof dest));
	OK(strcmp(dest, "xyz") == 0);
	OK(dest == __strncat_chk(dest, "xyz", 1, sizeof dest));
	OK(strcmp(dest, "xyzx") == 0);

	return 1;
}

int test_strcspn(void)
{
	OK(strcspn("", "") == 0);
	OK(strcspn("xyz", "") == 3);
	OK(strcspn("xyz", "z") == 2);
	OK(strcspn("xyzabc", "zxlyz") == 0);
	OK(strcspn("12344xyz", "0123456789") == 0);
	OK(strcspn("12344.", "./") == 5);

	return 1;
}

int test_strpbrk(void)
{
	char x1[] = "test";

	OK(strpbrk("", "") == NULL);
	OK(strpbrk(x1, "") == NULL);
	OK(strpbrk(x1, "x") == NULL);
	OK(strpbrk(x1, "t") == x1);
	OK(strpbrk(x1, "xyze") == x1+1);

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_strlen())
		return 1;

	if (!test_strcmp())
		return 1;

	if (!test_strncmp())
		return 1;

	if (!test_memcpy())
		return 1;

	if (!test_mempcpy())
		return 1;

	if (!test_memmove())
		return 1;

	if (!test_strspn())
		return 1;

	if (!test_strcpy())
		return 1;

	if (!test_strncpy())
		return 1;

	if (!test_strcat_chk())
		return 1;

	if (!test_memchr())
		return 1;

	if (!test_memrchr())
		return 1;

	if (!test_strchr())
		return 1;

	if (!test_strrchr())
		return 1;

	if (!test_strchrnul())
		return 1;

	if (!test_strncat_chk())
		return 1;

	if (!test_strcspn())
		return 1;

	if (!test_strpbrk())
		return 1;

	puts("OK");

	return 0;
}
