#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	if (strncmp("a", "aa", 1) != 0)
		return __LINE__;

	if (strncmp("a", "b", 0) != 0)
		return __LINE__;

	if (strncmp("blah a", "blah b", 6) >= 0)
		return __LINE__;

	if (strncmp("AAA", "AAA", 6) != 0)
		return __LINE__;

	puts("OK");

	return 0;
}
