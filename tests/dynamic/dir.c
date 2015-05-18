#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define OK(expr) \
	do { \
		if (!(expr)) \
		{ \
			printf("expression '%s' untrue at %d\n", \
				 #expr, __LINE__); \
			return 0; \
		} \
	} while (0)

int test_getcwd(void)
{
	char buf[100], *d;

	OK(0 == chdir("/"));
	OK(buf == getcwd(buf, sizeof buf));
	OK(!strcmp(buf, "/"));

	d = getcwd(NULL, 0);
	OK(NULL != d);
	OK(!strcmp(d, "/"));
	free(d);

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_getcwd())
		return 1;

	puts("OK");

	return 0;
}