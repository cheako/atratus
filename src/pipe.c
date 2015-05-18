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
	LIST_ANCHOR(struct wait_entry) wl;
	char buffer[0x1000];
};

struct pipe_filp
{
	struct filp fp;
	struct pipe_buffer *pb;
};

static void pipe_notify_waiters(struct pipe_buffer *pb)
{
	struct wait_entry *we;

	LIST_FOR_EACH(&pb->wl, we, item)
		ready_list_add(we->p);
}

static void pipe_wait_change(struct pipe_buffer *pb)
{
	struct wait_entry we;

	we.p = current;
	LIST_APPEND(&pb->wl, &we, item);
	schedule();
	LIST_REMOVE(&pb->wl, &we, item);
}

static int pipe_read(struct filp *f, void *buf, size_t size, loff_t *off, int block)
{
	struct pipe_filp *pfp = (void*) f;
	struct pipe_buffer *pb = pfp->pb;
	int bytesCopied = 0;

	while (size)
	{
		int sz;

		sz = pb->available;

		if (sz == 0)
		{
			int r;

			if (pb->closed)
				break;

			if (!block)
				break;

			r = process_pending_signal_check(current);
			if (r < 0)
			{
				if (!bytesCopied)
					bytesCopied = r;
				break;
			}

			pipe_wait_change(pb);
			continue;
		}

		if (sz > size)
			sz = size;

		if (sz + pb->head > sizeof pb->buffer)
			sz = sizeof pb->buffer - pb->head;

		memcpy(buf, &pb->buffer[pb->head], sz);

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

static int pipe_write(struct filp *f, const void *buf, size_t size, loff_t *off, int block)
{
	struct pipe_filp *pfp = (void*) f;
	struct pipe_buffer *pb = pfp->pb;
	int bytesCopied = 0;

	while (size && current->state != thread_terminated)
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

static void pipe_close(struct filp *fp)
{
	struct pipe_filp *pfp = (void*) fp;

	pfp->pb->closed++;
	if (pfp->pb->closed == 1)
		pipe_notify_waiters(pfp->pb);
	else if (pfp->pb->closed == 2)
		free(pfp->pb);
}

static int pipe_write_poll(struct filp *fp)
{
	struct pipe_filp *pfp = (void*) fp;
	struct pipe_buffer *pb = pfp->pb;
	int space = sizeof pb->buffer - pb->available;

	return space ? _L(POLLOUT) : 0;
}

static int pipe_read_poll(struct filp *fp)
{
	struct pipe_filp *pfp = (void*) fp;
	struct pipe_buffer *pb = pfp->pb;

	return pb->available ? _L(POLLIN) : 0;
}

static void pipe_poll_add(struct filp *fp, struct wait_entry *we)
{
	struct pipe_filp *pfp = (void*) fp;
	struct pipe_buffer *pb = pfp->pb;

	LIST_APPEND(&pb->wl, we, item);
}

static void pipe_poll_del(struct filp *fp, struct wait_entry *we)
{
	struct pipe_filp *pfp = (void*) fp;
	struct pipe_buffer *pb = pfp->pb;

	LIST_REMOVE(&pb->wl, we, item);
}

static const struct filp_ops pipe_write_ops = {
	.fn_write = &pipe_write,
	.fn_close = &pipe_close,
	.fn_poll = &pipe_write_poll,
	.fn_poll_add = &pipe_poll_add,
	.fn_poll_del = &pipe_poll_del,
};

static const struct filp_ops pipe_read_ops = {
	.fn_read = &pipe_read,
	.fn_close = &pipe_close,
	.fn_poll = &pipe_read_poll,
	.fn_poll_add = &pipe_poll_add,
	.fn_poll_del = &pipe_poll_del,
};

int pipe_create(struct filp **fp)
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
