#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	void *p, *p2;

	p = malloc(0);
	free(p);

	p = malloc(100);
	memset(p, 0, 100);
	free(p);

	p = malloc(10000);
	memset(p, 0, 10000);
	free(p);

	p = malloc(1000);
	strcpy(p, "hello");
	p2 = malloc(1000);
	p = realloc(p, 10000);

	strcmp(p, "hello");
	free(p);
	free(p2);

	puts("ok");
	return 0;
}
