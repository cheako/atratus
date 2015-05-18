#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char *haystack[] = {
	"a",
	"b",
	"bar",
	"foo",
	"master",
	"needle",
	"noodle",
	"stack",
	"test",
};

static int cmpfn(const void *a, const void *b)
{
	const char * const * as = a, * const * bs = b;
	return strcmp(*as, *bs);
}

int main(int argc, char **argv)
{
	char **r;
	char *p = "needle";

	r = bsearch(&p, haystack,
		sizeof haystack/sizeof haystack[0],
		sizeof (char*), cmpfn);

	if (!r)
	{
		puts("failed");
		return 1;
	}

	puts(*r);

	return (void*) r == (void*) &haystack[5] ? 0 : 1;
}
