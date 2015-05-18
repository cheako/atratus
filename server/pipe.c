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

struct pipe_buffer
{
	int head, available;
	int closed;
	struct wait_list wl;
	char buffer[0x1000];
};

struct pipe_filp
{
	filp fp;
	struct pipe_buffer *pb;
};

static void pipe_notify_waiters(struct pipe_buffer *pb)
{
	struct wait_entry *we;

	for (we = pb->wl.head; we; we = we->next)
		ready_list_add(we->p);
}

static void pipe_wait_change(struct pipe_buffer *pb)
{
	struct wait_entry we;

	we.p = current;
	wait_entry_append(&pb->wl, &we);
	current->state = thread_stopped;
	yield();
	current->state = thread_running;
	wait_entry_remove(&pb->wl, &we);
}

static int pipe_read(filp *f, void *buf, size_t size, loff_t *off, int block)
{
	struct pipe_filp *pfp = (void*) f;
	struct pipe_buffer *pb = pfp->pb;
	int bytesCopied = 0;

	while (size)
	{
		int sz;
		int r;

		sz = pb->available;

		if (sz == 0)
		{
			if (pb->closed)
				break;

			if (!block)
				break;

			pipe_wait_change(pb);
			continue;
		}

		if (sz > size)
			sz = size;

		if (sz + pb->head > sizeof pb->buffer)
			sz = sizeof pb->buffer - pb->head;

		r = current->ops->memcpy_to(buf, &pb->buffer[pb->head], sz);
		if (r < 0)
		{
			if (bytesCopied)
				break;
			return -_L(EFAULT);
		}
		bytesCopied += sz;
		buf = (char*) buf + sz;
		size -= sz;
		pb->head += sz;
		pb->head %= sizeof pb->buffer;
		pb->available -= sz;

		pipe_notify_waiters(pb);
	}

	return bytesCopied;
}

static int pipe_write(filp *f, const void *buf, size_t size, loff_t *off, int block)
{
	struct pipe_filp *pfp = (void*) f;
	struct pipe_buffer *pb = pfp->pb;
	int bytesCopied = 0;

	while (size)
	{
		int sz;
		int r;
		int space = sizeof pb->buffer - pb->available;
		int pos = (pb->head + pb->available) % sizeof pb->buffer;

		if (space == 0)
		{
			if (pb->closed)
				break;
			if (!block)
				break;

			pipe_wait_change(pb);
			continue;
		}

		sz = space;

		if (sz > size)
			sz = size;

		if (pos + sz > sizeof pb->buffer)
			sz = sizeof pb->buffer - pos;

		r = current->ops->memcpy_from(&pb->buffer[pos], buf, sz);
		if (r < 0)
		{
			if (bytesCopied)
				break;
			return -_L(EFAULT);
		}

		bytesCopied += sz;
		buf = (char*) buf + sz;
		size -= sz;
		pb->available += sz;

		pipe_notify_waiters(pb);
	}

	return bytesCopied;
}

static void pipe_close(filp *fp)
{
	struct pipe_filp *pfp = (void*) fp;

	pfp->pb->closed++;
	if (pfp->pb->closed == 1)
		pipe_notify_waiters(pfp->pb);
	else if (pfp->pb->closed == 2)
		free(pfp->pb);
}

static const struct filp_ops pipe_write_ops = {
	.fn_write = &pipe_write,
	.fn_close = &pipe_close,
};

static const struct filp_ops pipe_read_ops = {
	.fn_read = &pipe_read,
	.fn_close = &pipe_close,
};

static int create_pipe(filp **fp)
{
	struct pipe_filp *write_pfp = NULL;
	struct pipe_filp *read_pfp = NULL;
	struct pipe_buffer *pb;

	fp[0] = NULL;
	fp[1] = NULL;

	pb = malloc(sizeof *pb);
	if (!pb)
		goto error;
	memset(pb, 0, sizeof *pb);

	read_pfp = malloc(sizeof *read_pfp);
	if (!read_pfp)
		goto error;
	memset(read_pfp, 0, sizeof *read_pfp);
	init_fp(&read_pfp->fp, &pipe_read_ops);
	read_pfp->pb = pb;

	write_pfp = malloc(sizeof *write_pfp);
	if (!write_pfp)
		goto error;
	memset(write_pfp, 0, sizeof *write_pfp);
	init_fp(&write_pfp->fp, &pipe_write_ops);
	write_pfp->pb = pb;

	fp[0] = &read_pfp->fp;
	fp[1] = &write_pfp->fp;
	return 0;

error:
	free(pb);
	free(read_pfp);
	free(write_pfp);
	return -_L(ENOMEM);
}

int do_pipe(int *fds)
{
	filp *fp[2];
	int r;
	int fd0, fd1;

	r = create_pipe(fp);
	if (r < 0)
		return r;

	fd0 = alloc_fd();
	if (fd0 < 0)
	{
		filp_close(fp[0]);
		filp_close(fp[1]);
		return -_L(EMFILE);
	}

	current->handles[fd0].fp = fp[0];
	current->handles[fd0].flags = 0;

	fd1 = alloc_fd();
	if (fd1 < 0)
	{
		do_close(fd0);
		filp_close(fp[1]);
		return -_L(EMFILE);
	}

	current->handles[fd1].fp = fp[1];
	current->handles[fd1].flags = 0;

	fds[0] = fd0;
	fds[1] = fd1;

	dprintf("fds[] -> %d, %d\n", fds[0], fds[1]);

	return 0;
}
