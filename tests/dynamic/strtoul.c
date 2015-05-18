#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	if (0 != strtoul("", NULL, 10))
		return 1;
	if (1 != strtoul("1", NULL, 10))
		return 1;
	if (10 != strtoul("10", NULL, 10))
		return 1;
	if (8765432 != strtoul("8765432", NULL, 10))
		return 1;
	if (1 != strtoul("+1", NULL, 10))
		return 1;
	if (-1 != strtoul("-1", NULL, 10))
		return 1;
	if (0x10 != strtoul("0x10", NULL, 16))
		return 1;
	printf("ok\n");
	return 0;
}
