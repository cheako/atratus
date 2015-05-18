/*
 * Console emulation
 *
 * Copyright (C) 2011 - 2013 Mike McCormack
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
#include <winnt.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <assert.h>
#include "filp.h"
#include "process.h"
#include "tty.h"
#include "linux-errno.h"
#include "linux-defines.h"
#include "debug.h"

static void con_poll_add(filp *f, struct wait_entry *we);
static void con_poll_del(filp *f, struct wait_entry *we);

static int con_is_canonical(con_filp *con)
{
	return con->tios.c_lflag & ICANON;
}

/*
 * Process input characters into an input string
 * return number of characters ready to read
 */
static int con_process_input(con_filp *con)
{
	int i, pos, end;

	if (!con_is_canonical(con))
		return con->ready_count;

	/* remove VERASE characters, find line feed */
	pos = 0;
	end = -1;
	for (i = 0; i < con->ready_count; i++)
	{
		char ch = con->ready_data[i];

		/* once we find a line feed character, just copy */
		if (end < 0 && !con->eof)
		{
			if (pos && ch == con->tios.c_cc[VERASE])
			{
				pos--;
				continue;
			}

			if ((con->tios.c_iflag & INLCR) && ch == '\n')
				ch = '\r';
			else if ((con->tios.c_iflag & ICRNL) && ch == '\r')
				ch = '\n';

			if ((con->tios.c_iflag & IUCLC) && ch >= 'A' && ch <= 'Z')
				ch += ('a' - 'A');

			if (ch == '\n')
			{
				end = pos;
				con->ready_data[pos] = ch;
			}
			else if (ch == con->tios.c_cc[VEOF])
			{
				end = pos - 1;
				con->eof = 1;
			}
		}

		if (pos != i)
			con->ready_data[pos] = ch;
		pos++;
	}

	con->ready_count -= (i - pos);

	return end + 1;
}

static int con_read(filp *f, void *buf, size_t size, loff_t *ofs, int block)
{
	con_filp *con = (con_filp*) f;
	int ret = 0;
	struct wait_entry we;
	int done = 0;

	we.p = current;
	con_poll_add(&con->fp, &we);

	while (ret < size && !con->eof && !done)
	{
		BOOL wait = 0;
		size_t len;

		con->ops->fn_lock(con);
		assert(con->ready_count >= 0);
		len = con_process_input(con);
		if (len)
		{
			if (len > size)
				len = size;

			int r;
			r = current->ops->memcpy_to(buf, con->ready_data, len);
			if (r < 0)
			{
				if (ret > 0)
					break;
				return -_L(EFAULT);
			}
			buf = (char*)buf + len;
			ret += len;

			/* move everything to the front */
			con->ready_count -= len;
			memmove(con->ready_data, con->ready_data+len, con->ready_count);
			done = 1;
		}
		else
		{
			wait = 1;
		}
		con->ops->fn_unlock(con);

		if (wait && !block)
			break;

		if (wait)
		{
			current->state = thread_stopped;
			yield();
			current->state = thread_running;
		}
	}

	con_poll_del(&con->fp, &we);

	dprintf("con_read r = %d/%d\n", ret, size);

	return ret;
}

void tty_input_add_char(con_filp *con, char ch)
{
	struct wait_entry *we;

	con->ops->fn_lock(con);

	/* add data to buffer */
	if (con->ready_count < sizeof con->ready_data)
		con->ready_data[con->ready_count++] = ch;

	/* TODO: send only to the controlling terminal */
	for (we = con->wl.head; we; we = we->next)
		ready_list_add(we->p);

	con->ops->fn_unlock(con);
}

void tty_input_add_string(con_filp *con, const char *string)
{
	struct wait_entry *we;
	int len = strlen(string);

	con->ops->fn_lock(con);
	if ((con->ready_count + len) <= sizeof con->ready_data)
	{
		memcpy(&con->ready_data[con->ready_count], string, len);
		con->ready_count += len;
	}

	for (we = con->wl.head; we; we = we->next)
		ready_list_add(we->p);

	con->ops->fn_unlock(con);
}

/* write to the terminal, observing termios settings */
static int con_write_output(con_filp *con, unsigned char ch)
{
	switch (ch)
	{
	case 0x0d:
		if (con->tios.c_oflag & ONLRET)
			return 0;
		if (con->tios.c_oflag & OCRNL)
			ch = 0x0d;
		break;
	case 0x0a:
		if (con->tios.c_oflag & ONLCR)
			con->ops->fn_write(con, 0x0d);
		return con->ops->fn_write(con, 0x0a);
	}

	/* map lower case to upper case */
	if (con->tios.c_oflag & OLCUC)
	{
		if (ch >= 'a' && ch <= 'z')
			ch = ch - 'a' + 'A';
	}

	return con->ops->fn_write(con, ch);
}

static void tty_debug_dump_buffer(const unsigned char *buffer, size_t sz)
{
	char out[30];
	int n = 0;
	int i;

	for (i = 0; i < sz && n < sizeof out - 3; i++)
	{
		unsigned char ch = buffer[i];
		if (ch >= 0x20 && ch < 0x80)
			out[n++] = ch;
		else
		{
			/* write as octal */
			out[n++] = '\\';
			out[n++] = '0' + ((ch >> 6) & 3);
			out[n++] = '0' + ((ch >> 3) & 7);
			out[n++] = '0' + (ch & 7);
		}
	}

	dprintf("tty out -> '%.*s'\n", n, out);
}

static int con_write(filp *f, const void *buf, size_t size, loff_t *off)
{
	con_filp *con = (con_filp*) f;
	DWORD written = 0;
	unsigned char *p = NULL;
	unsigned char buffer[0x1000];
	ULONG buf_remaining = 0;
	int r, i;

	for (i = 0; i < size; i++)
	{
		if (buf_remaining == 0)
		{
			int sz = size;
			if (sz > sizeof buffer)
				sz = sizeof buffer;
			r = current->ops->memcpy_from(buffer, buf, sz);
			if (r < 0)
			{
				dprintf("memcpy_from failed\n");
				if (written)
					break;
				return r;
			}
			tty_debug_dump_buffer(buffer, sz);
			buf_remaining = sz;
			buf = (char*)buf + buf_remaining;
			p = buffer;
		}
		if (buf_remaining == 0)
			break;
		r = con_write_output(con, *p);
		if (r < 0)
			break;
		written++;
		buf_remaining--;
		p++;
	}

	dprintf("ret = %d\n", written);

	return written;
}

static int con_set_termios(con_filp *con, void *p)
{
	int r;
	/*
	 * There's two or three different termios structures.
	 * TODO: use the kernel structure, not the libc one
	 */
	STATIC_ASSERT(sizeof con->tios == 60);

	r = current->ops->memcpy_from(&con->tios, p, sizeof con->tios);
	if (r < 0)
		return r;
	dprintf("tios: %s %s %s %s %s\n",
		 (con->tios.c_oflag & ONLRET) ? "ONLRET" : "~ONLRET",
		 (con->tios.c_oflag & OCRNL) ? "OCRNL" : "~OCRNL",
		 (con->tios.c_oflag & ONLCR) ? "ONLCR" : "~ONLCR",
		 (con->tios.c_oflag & OLCUC) ? "OLCUC" : "~OLCUC",
		 (con->tios.c_oflag & OPOST) ? "OPOST" : "~POST"
	);

	return 0;
}

static int con_get_termios(con_filp *con, void *p)
{
	dprintf("get termios(%p)\n", p);
	return current->ops->memcpy_to(p, &con->tios, sizeof con->tios);
}

static int con_get_winsize(con_filp *con, void *ptr)
{
	struct winsize ws;

	con->ops->fn_get_winsize(con, &ws);
	return current->ops->memcpy_to(ptr, &ws, sizeof ws);
}

static int con_ioctl(filp *f, int cmd, unsigned long arg)
{
	con_filp *con = (con_filp*) f;
	int *pgrp;
	int r = 0;

	switch (cmd)
	{
	case TIOCGPGRP:
		pgrp = (int*)arg;
		*pgrp = f->pgid;
		break;
	case TIOCSPGRP:
		f->pgid = arg;
		break;
	case TIOCS:
		return con_set_termios(con, (void*)arg);
	case TIOCG:
		return con_get_termios(con, (void*)arg);
	case TIOCGWINSZ:
		return con_get_winsize(con, (void*)arg);
	default:
		dprintf("unknown tty ioctl(%08x, %08x)\n", cmd, arg);
		r = -_L(EINVAL);
	}

	return r;
}

static int con_poll(filp *f)
{
	int events = 0;
	con_filp *con = (con_filp*) f;
	con->ops->fn_lock(con);
	if (0 != con_process_input(con))
		events |= _l_POLLIN;
	events |= _l_POLLOUT;
	con->ops->fn_unlock(con);
	return events;
}

static void con_poll_add(filp *f, struct wait_entry *we)
{
	con_filp *con = (con_filp*) f;

	con->ops->fn_lock(con);
	wait_entry_append(&con->wl, we);
	con->ops->fn_unlock(con);
}

static void con_poll_del(filp *f, struct wait_entry *we)
{
	con_filp *con = (con_filp*) f;

	con->ops->fn_lock(con);
	wait_entry_remove(&con->wl, we);
	con->ops->fn_unlock(con);
}

static const struct filp_ops con_file_ops = {
	.fn_read = &con_read,
	.fn_write = &con_write,
	.fn_ioctl = &con_ioctl,
	.fn_poll = &con_poll,
	.fn_poll_add = &con_poll_add,
	.fn_poll_del = &con_poll_del,
};

void tty_init(con_filp *con)
{
	init_fp(&con->fp, &con_file_ops);

	con->tios.c_lflag = ICANON | ECHO;
	con->tios.c_cc[VERASE] = 8;
	con->tios.c_cc[VEOF] = 4;
	con->tios.c_oflag = ONLCR | OPOST;
	con->eof = 0;
	con->ready_count = 0;
}
