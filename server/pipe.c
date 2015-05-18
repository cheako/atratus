/*
 * pipe emulation
 *
 * Copyright (C) 2012 - 2013 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include <windows.h>
#include "pipe.h"
#include "filp.h"
#include "process.h"
#include "linux-errno.h"
#include "debug.h"

static int pipe_read(filp *f, void *buf, size_t size, loff_t *off, int block)
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
	init_fp(fp, &pipe_ops);

	fds[0] = alloc_fd();
	if (fds[0] < 0)
	{
		free(fp);
		return -_L(ENOMEM);
	}

	current->handles[fds[0]].fp = fp;
	current->handles[fds[0]].flags = 0;

	fds[1] = alloc_fd();
	if (fds[1] < 0)
	{
		/* FIXME: leaks fd0 */
		free(fp);
		return -_L(ENOMEM);
	}

	current->handles[fds[1]].fp = fp;
	current->handles[fds[1]].flags = 0;

	dprintf("fds[] -> %d, %d\n", fds[0], fds[1]);

	return 0;
}
