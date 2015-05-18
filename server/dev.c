#include <windows.h>
#include <stdio.h>
#include "ntapi.h"
#include "filp.h"
#include "linux-errno.h"
#include "linux-defines.h"
#include "debug.h"
#include "process.h"
#include "tty.h"

static int dev_stat64(struct fs *fs, const char *path,
			struct stat64 *statbuf, bool follow_links)
{
	return -_L(ENOENT);
}

static int dev_open(struct fs *fs, const char *file, int flags, int mode)
{
	filp *fp = NULL;
	int fd;

	dprintf("opening %s\n", file);

	while (file[0] == '/')
		file++;

	if (!strcmp(file, "tty"))
		fp = current->tty;

	if (!fp)
		return -_L(ENOENT);

	fd = alloc_fd();
	if (fd < 0)
		return -_L(ENOMEM);

	current->handles[fd] = fp;

	return fd;
}

static struct fs devfs =
{
	.root = "/dev/",
	.open = &dev_open,
	.stat64 = &dev_stat64,
};

void devfs_init(void)
{
	fs_add(&devfs);
}
