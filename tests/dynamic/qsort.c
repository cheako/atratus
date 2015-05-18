#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *haystack[] = {
	"foo",
	"master",
	"needle",
	"noodle",
	"stack",
	"test",
	"a",
	"b",
	"bar",
};

static int cmpfn(const void *a, const void *b)
{
	const char * const * as = a, * const * bs = b;
	return strcmp(*as, *bs);
}

int main(int argc, char **argv)
{
	int nmemb = sizeof haystack/sizeof haystack[0];
	int i;

	qsort(haystack, nmemb, sizeof haystack[0], cmpfn);

	for (i = 1; i < nmemb; i++)
		if (0 <= strcmp(haystack[i - 1], haystack[i]))
			return 1;

	printf("OK\n");

	return 0;
}
