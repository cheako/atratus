#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *foo = NULL;

int test_sprintf(void)
{
	char out[0x100];
	sprintf(out, "%d", 0);
	if (strcmp("0", out))
		return 1;

	sprintf(out, "%d", 123);
	if (strcmp("123", out))
		return 1;

	sprintf(out, "%d", -1);
	if (strcmp("-1", out))
		return 1;

	sprintf(out, "test");
	if (strcmp("test", out))
		return 1;

	sprintf(out, "%s", "test");
	if (strcmp("test", out))
		return 1;

	sprintf(out, "%s %s", "test", "123");
	if (strcmp("test 123", out))
		return 1;

	sprintf(out, "%c", 'x');
	if (strcmp("x", out))
		return 1;

	sprintf(out, "%s", foo);
	if (strcmp("(null)", out))
		return 1;

	sprintf(out, "%x", 0x100);
	if (strcmp("100", out))
		return 1;

	sprintf(out, "%o", 0);
	if (strcmp("0", out))
		return 1;

	sprintf(out, "%o", 10);
	if (strcmp("12", out))
		return 1;

	sprintf(out, "%o", 64);
	if (strcmp("100", out))
		return 1;

	sprintf(out, "%4d", 64);
	if (strcmp("  64", out))
		return 1;

	sprintf(out, "%4d", 1000);
	if (strcmp("1000", out))
		return 1;

	sprintf(out, "%4d", 99999);
	if (strcmp("99999", out))
		return 1;

	sprintf(out, "%04o", 9);
	if (strcmp("0011", out))
		return 1;

	sprintf(out, "%04d", 9);
	if (strcmp("0009", out))
		return 1;

	sprintf(out, "%01x", 0x90);
	if (strcmp("90", out))
		return 1;

	sprintf(out, "%09x", 0x90);
	if (strcmp("000000090", out))
		return 1;

	sprintf(out, "%4x", 0x123);
	if (strcmp(" 123", out))
		return 1;

	sprintf(out, "%u", ~0);
	if (strcmp("4294967295", out))
		return 1;

	sprintf(out, "%04u", 0);
	if (strcmp("0000", out))
		return 1;

	sprintf(out, "%llu %llu", 1LL, 2LL);
	if (strcmp("1 2", out))
		return 1;

	sprintf(out, "fn(): %c\n", 'x');
	if (strcmp("fn(): x\n", out))
		return 1;

	sprintf(out, "%%x");
	if (strcmp("%x", out))
		return 1;

	sprintf(out, "%*x", 4, 0x123);
	if (strcmp(" 123", out))
		return 1;

	sprintf(out, "%*s", 4, "x");
	if (strcmp("   x", out))
		return 1;

	return 0;
}

int test_asprintf(void)
{
	char *out = NULL;
	int r;

	r = asprintf(&out, "%d", 0);
	if (r != 1)
		return 1;
	if (strcmp("0", out))
		return 1;
	free(out);

	r = asprintf(&out, "%c%c%cbar", 'f', 'o', 'o');
	if (r != 6)
		return 1;
	if (strcmp("foobar", out))
		return 1;
	free(out);

	return 0;
}

int test_snprintf(void)
{
	char out[0x100];
	int n;

	n = snprintf(out, 1, "%d", 100);
	if (strcmp("", out))
		return 1;
	if (n != 3)
		return 1;

	n = snprintf(out, 2, "%d", 100);
	if (strcmp("1", out))
		return 1;
	if (n != 3)
		return 1;

	n = snprintf(out, 3, "%d", 100);
	if (strcmp("10", out))
		return 1;
	if (n != 3)
		return 1;

	n = snprintf(out, 4, "%d", 100);
	if (strcmp("100", out))
		return 1;
	if (n != 3)
		return 1;

	out[0] = 0;
	n = snprintf(out, 0, "%d", 100);
	if (out[0] != 0)
		return 1;
	if (n != 3)
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	if (test_sprintf())
		return 1;

	if (test_asprintf())
		return 1;

	if (test_snprintf())
		return 1;

	printf("ok\n");

	return 0;
}
