#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	int r;

	r = fork();
	if (r == 0)
	{
		_exit(0x123);
	}
	else
	{
		int child = r;
		int status = 0;
		r = waitpid(-1, &status, 0);
		if (r != child)
			return 1;

		if (status != 0x2300)
			return 1;
	}
	printf("ok\n");
	return 0;
}
