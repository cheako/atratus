#include "pipe.h"
#include "linux-errno.h"

int do_pipe(int *fds)
{
	return -_L(ENOSYS);
}

