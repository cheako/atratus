#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define OK(expr) \
	do { \
		if (!(expr)) \
		{ \
			printf("expression '%s' untrue at %d\n", \
				 #expr, __LINE__); \
			return 0; \
		} \
	} while (0)

int test_create_pipe(void)
{
	int fds[2] = {-1, -1};

	OK(0 == pipe(fds));
	OK(0 == close(fds[0]));
	OK(0 == close(fds[1]));

	return 1;
}

int main(int argc, char **argv)
{
	if (!test_create_pipe())
		return 1;

	printf("OK\n");

	return 0;
}
