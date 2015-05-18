/*
 * null device
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
#include "null.h"

static int null_read(struct filp *f, void *buf, user_size_t size, loff_t *off, int block)
{
	return 0;
}

static const struct filp_ops null_ops = {
	.fn_read = &null_read,
};

struct filp* null_fp_get(void)
{
	struct filp *fp;

	fp = malloc(sizeof (*fp));
	if (!fp)
		return NULL;

	init_fp(fp, &null_ops);

	dprintf("null fd -> %p\n", fp);

	return fp;
}
