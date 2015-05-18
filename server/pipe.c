#include <windows.h>
#include "pipe.h"
#include "filp.h"
#include "process.h"
#include "linux-errno.h"
#include "debug.h"

static int pipe_read(filp *f, void *buf, size_t size, loff_t *off)
{
	return 0;
}

static int pipe_write(filp *f, const void *buf, size_t size, loff_t *off)
{
	return 0;
}

static const struct filp_ops pipe_ops = {
	.fn_read = &pipe_read,
	.fn_write = &pipe_write,
};

int do_pipe(int *fds)
{
	filp *fp;

	fp = malloc(sizeof (*fp));
	if (!fp)
		return -_L(ENOMEM);

	memset(fp, 0, sizeof *fp);
	fp->ops = &pipe_ops;
	fp->pgid = 0;
	fp->handle = INVALID_HANDLE_VALUE;
	fp->offset = 0;

	fds[0] = alloc_fd();
	if (fds[0] < 0)
	{
		free(fp);
		return -_L(ENOMEM);
	}

	current->handles[fds[0]] = fp;

	fds[1] = alloc_fd();
	if (fds[1] < 0)
	{
		/* FIXME: leaks fd0 */
		free(fp);
		return -_L(ENOMEM);
	}

	current->handles[fds[1]] = fp;

	dprintf("fds[] -> %d, %d\n", fds[0], fds[1]);

	return 0;
}
