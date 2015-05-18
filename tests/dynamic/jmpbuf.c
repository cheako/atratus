#include <stdio.h>
#include <setjmp.h>
#include <stdlib.h>

#define STATIC_ASSERT(expr) \
	do { \
		char _sa[(expr) ? 1 : -1]; \
		(void) _sa; \
	} while(0)

int main(int argc, char **argv)
{
	jmp_buf env;
	int r;
	volatile int x = 0x67895432;

	STATIC_ASSERT(sizeof env == 156);

	r = setjmp(env);
	if (r)
	{
		if (x != 0x67895432)
			exit(1);
		if (r == 2)
			goto again;
		goto finish;
	}

	longjmp(env, 2);

again:
	longjmp(env, 0);

	printf("fail\n");

	exit(1);
finish:
	printf("ok\n");
	exit(0);
}
