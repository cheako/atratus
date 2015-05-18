/*
 * device file emulation
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
#include "random.h"

static struct filp* dev_open(struct fs *fs, const char *file, int flags,
			int mode, int follow_links)
{
	struct filp *fp = NULL;

	dprintf("opening %s\n", file);

	while (file[0] == '/')
		file++;

	if (!strcmp(file, "tty"))
	{
		fp = current->tty;
		fp->refcount++;
	}

	if (!strcmp(file, "null"))
		fp = null_fp_get();

	if (!strcmp(file, "zero"))
		fp = null_fp_get();

	if (!strcmp(file, "urandom"))
		fp = random_fp_get();

	if (!fp)
		return L_ERROR_PTR(ENOENT);

	return fp;
}

static struct fs devfs =
{
	.root = "/dev",
	.open = &dev_open,
};

void devfs_init(void)
{
	fs_add(&devfs);
}
