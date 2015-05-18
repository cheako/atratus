/*
 * random device
 *
 * Copyright (C) 2013 Mike McCormack
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
#include "random.h"

extern BOOLEAN (APIENTRY *pRtlGenRandom)(void *Buffer, ULONG Size);

static int random_read(struct filp *f, void *buf, size_t size, loff_t *off, int block)
{
	size_t i;

	dprintf("random_read(%p,%d)\n", buf, size);

	/* not so cryptographically secure :-( */
	for (i = 0; i < size; i += 4)
	{
		unsigned int r = rand();
		unsigned int *p = buf;
		if ((size - i) >= 4)
			memcpy(&p[i/4], &r, 4);
		else
			memcpy(&p[i/4], &r, size - i);
	}

	return size;
}

static int random_poll(struct filp *f)
{
	dprintf("random_poll()\n");
	return _L(POLLIN);
}

static const struct filp_ops random_ops = {
	.fn_read = &random_read,
	.fn_poll = &random_poll,
};

struct filp* random_fp_get(void)
{
	struct filp *fp;

	fp = malloc(sizeof (*fp));
	if (!fp)
		return NULL;

	init_fp(fp, &random_ops);

	dprintf("random fd -> %p\n", fp);

	return fp;
}
