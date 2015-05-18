#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	char *p, *p2;
	int i;

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
	p[999] = 'x';
	p2 = malloc(1000);
	p = realloc(p, 10000);

	if (strcmp(p, "hello"))
		return 1;
	if (p[999] != 'x')
		return 1;
	free(p);
	free(p2);

	free(NULL);

	p = malloc(1);
	p2 = malloc(10);
	for (i = 2; i < 1000; i++)
	{
		p = realloc(p, i);
		p2 = realloc(p2, i * 2);
	}

	free(p);

	p = strdup("hello");
	if (strcmp("hello", p))
		return 1;

	puts("ok");
	return 0;
}
