#include <stdio.h>
#include "ok.h"

__thread int x;

int test_tls_read(void)
{
	OK(x == 10);

	return 1;
}

int main(int argc, char **argv)
{
	x = 10;

	if (!test_tls_read())
		return 1;

	printf("OK\n");
	return 0;
}
