/*
 * proc file emulation
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
#include <stdio.h>
#include "ntapi.h"
#include "filp.h"
#include "linux-errno.h"
#include "linux-defines.h"
#include "debug.h"
#include "process.h"
#include "tty.h"
#include "null.h"
#include "zero.h"

struct procfs_filp
{
	struct filp fp;
	int inode;
	int mode;
};

static int proc_stat(struct filp *fp, struct stat64 *statbuf)
{
	struct procfs_filp *pfp = (void*) fp;

	memset(statbuf, 0, sizeof *statbuf);
	statbuf->st_mode = pfp->mode;

	return 0;
}

static int proc_getdents(struct filp *fp, void *de,
			unsigned int count, fn_add_dirent add_de)
{
	struct procfs_filp *pfp = (void*) fp;
	(void) pfp;
	return -_L(EPERM);
}

static const struct filp_ops proc_file_ops = {
	.fn_getdents = &proc_getdents,
	.fn_stat = &proc_stat,
};

static struct filp* proc_open(struct fs *fs, const char *file, int flags,
			int mode, int follow_links)
{
	struct procfs_filp *pfp = NULL;

	dprintf("opening %s\n", file);

	while (file[0] == '/')
		file++;

	if (file[0] == 0)
	{
		dprintf("open proc!\n");

		pfp = malloc(sizeof (*pfp));
		if (!pfp)
			return L_ERROR_PTR(ENOMEM);

		init_fp(&pfp->fp, &proc_file_ops);
		pfp->mode = 040755; /* directory */
		pfp->inode = 1;
	}

	if (!pfp)
		return L_ERROR_PTR(ENOENT);

	return &pfp->fp;
}

static struct fs procfs =
{
	.root = "/proc",
	.open = &proc_open,
};

void procfs_init(void)
{
	fs_add(&procfs);
}
