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

static void tty_poll_add(filp *f, struct wait_entry *we);
static void tty_poll_del(filp *f, struct wait_entry *we);

static int tty_is_canonical(tty_filp *tty)
{
	return tty->tios.c_lflag & ICANON;
}

/*
 * Process input characters into an input string
 * return number of characters ready to read
 */
static int tty_process_input(tty_filp *tty)
{
	int i, pos, end;

	if (!tty_is_canonical(tty))
		return tty->ready_count;

	/* remove VERASE characters, find line feed */
	pos = 0;
	end = -1;
	for (i = 0; i < tty->ready_count; i++)
	{
		char ch = tty->ready_data[i];

		/* once we find a line feed character, just copy */
		if (end < 0 && !tty->eof)
		{
			if (pos && ch == tty->tios.c_cc[VERASE])
			{
				pos--;
				continue;
			}

			if ((tty->tios.c_iflag & INLCR) && ch == '\n')
				ch = '\r';
			else if ((tty->tios.c_iflag & ICRNL) && ch == '\r')
				ch = '\n';

			if ((tty->tios.c_iflag & IUCLC) && ch >= 'A' && ch <= 'Z')
				ch += ('a' - 'A');

			if (ch == '\n')
			{
				end = pos;
				tty->ready_data[pos] = ch;
			}
			else if (ch == tty->tios.c_cc[VEOF])
			{
				end = pos - 1;
				tty->eof = 1;
			}
		}

		if (pos != i)
			tty->ready_data[pos] = ch;
		pos++;
	}

	tty->ready_count -= (i - pos);

	return end + 1;
}

static int tty_read(filp *f, void *buf, size_t size, loff_t *ofs, int block)
{
	tty_filp *tty = (tty_filp*) f;
	int ret = 0;
	struct wait_entry we;
	int done = 0;

	we.p = current;
	tty_poll_add(&tty->fp, &we);

	while (ret < size && !tty->eof && !done)
	{
		BOOL wait = 0;
		size_t len;

		tty->ops->fn_lock(tty);
		assert(tty->ready_count >= 0);
		len = tty_process_input(tty);
		if (len)
		{
			if (len > size)
				len = size;

			int r;
			r = current->ops->memcpy_to(buf, tty->ready_data, len);
			if (r < 0)
			{
				if (ret > 0)
					break;
				return -_L(EFAULT);
			}
			buf = (char*)buf + len;
			ret += len;

			/* move everything to the front */
			tty->ready_count -= len;
			memmove(tty->ready_data, tty->ready_data+len, tty->ready_count);
			done = 1;
		}
		else
		{
			wait = 1;
		}
		tty->ops->fn_unlock(tty);

		if (wait && !block)
			break;

		if (wait)
		{
			current->state = thread_stopped;
			yield();
			current->state = thread_running;
		}
	}

	tty_poll_del(&tty->fp, &we);

	dprintf("tty_read r = %d/%d\n", ret, size);

	return ret;
}

void tty_input_add_char(tty_filp *tty, char ch)
{
	struct wait_entry *we;

	tty->ops->fn_lock(tty);

	/* add data to buffer */
	if (tty->ready_count < sizeof tty->ready_data)
		tty->ready_data[tty->ready_count++] = ch;

	/* TODO: send only to the controlling terminal */
	for (we = tty->wl.head; we; we = we->next)
		ready_list_add(we->p);

	tty->ops->fn_unlock(tty);
}

void tty_input_add_string(tty_filp *tty, const char *string)
{
	struct wait_entry *we;
	int len = strlen(string);

	tty->ops->fn_lock(tty);
	if ((tty->ready_count + len) <= sizeof tty->ready_data)
	{
		memcpy(&tty->ready_data[tty->ready_count], string, len);
		tty->ready_count += len;
	}

	for (we = tty->wl.head; we; we = we->next)
		ready_list_add(we->p);

	tty->ops->fn_unlock(tty);
}

/* write to the terminal, observing termios settings */
static int tty_write_output(tty_filp *tty, unsigned char ch)
{
	switch (ch)
	{
	case 0x0d:
		if (tty->tios.c_oflag & ONLRET)
			return 0;
		if (tty->tios.c_oflag & OCRNL)
			ch = 0x0d;
		break;
	case 0x0a:
		if (tty->tios.c_oflag & ONLCR)
			tty->ops->fn_write(tty, 0x0d);
		return tty->ops->fn_write(tty, 0x0a);
	}

	/* map lower case to upper case */
	if (tty->tios.c_oflag & OLCUC)
	{
		if (ch >= 'a' && ch <= 'z')
			ch = ch - 'a' + 'A';
	}

	return tty->ops->fn_write(tty, ch);
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

static int tty_write(filp *f, const void *buf, size_t size, loff_t *off)
{
	tty_filp *tty = (tty_filp*) f;
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
		r = tty_write_output(tty, *p);
		if (r < 0)
			break;
		written++;
		buf_remaining--;
		p++;
	}

	dprintf("ret = %d\n", written);

	return written;
}

static int tty_set_termios(tty_filp *tty, void *p)
{
	int r;
	/*
	 * There's two or three different termios structures.
	 * TODO: use the kernel structure, not the libc one
	 */
	STATIC_ASSERT(sizeof tty->tios == 60);

	r = current->ops->memcpy_from(&tty->tios, p, sizeof tty->tios);
	if (r < 0)
		return r;
	dprintf("tios: %s %s %s %s %s\n",
		 (tty->tios.c_oflag & ONLRET) ? "ONLRET" : "~ONLRET",
		 (tty->tios.c_oflag & OCRNL) ? "OCRNL" : "~OCRNL",
		 (tty->tios.c_oflag & ONLCR) ? "ONLCR" : "~ONLCR",
		 (tty->tios.c_oflag & OLCUC) ? "OLCUC" : "~OLCUC",
		 (tty->tios.c_oflag & OPOST) ? "OPOST" : "~POST"
	);

	return 0;
}

static int tty_get_termios(tty_filp *tty, void *p)
{
	dprintf("get termios(%p)\n", p);
	return current->ops->memcpy_to(p, &tty->tios, sizeof tty->tios);
}

static int tty_get_winsize(tty_filp *tty, void *ptr)
{
	struct winsize ws;

	tty->ops->fn_get_winsize(tty, &ws);
	return current->ops->memcpy_to(ptr, &ws, sizeof ws);
}

static int tty_ioctl(filp *f, int cmd, unsigned long arg)
{
	tty_filp *tty = (tty_filp*) f;
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
		return tty_set_termios(tty, (void*)arg);
	case TIOCG:
		return tty_get_termios(tty, (void*)arg);
	case TIOCGWINSZ:
		return tty_get_winsize(tty, (void*)arg);
	default:
		dprintf("unknown tty ioctl(%08x, %08x)\n", cmd, arg);
		r = -_L(EINVAL);
	}

	return r;
}

static int tty_poll(filp *f)
{
	int events = 0;
	tty_filp *tty = (tty_filp*) f;
	tty->ops->fn_lock(tty);
	if (0 != tty_process_input(tty))
		events |= _l_POLLIN;
	events |= _l_POLLOUT;
	tty->ops->fn_unlock(tty);
	return events;
}

static void tty_poll_add(filp *f, struct wait_entry *we)
{
	tty_filp *tty = (tty_filp*) f;

	tty->ops->fn_lock(tty);
	wait_entry_append(&tty->wl, we);
	tty->ops->fn_unlock(tty);
}

static void tty_poll_del(filp *f, struct wait_entry *we)
{
	tty_filp *tty = (tty_filp*) f;

	tty->ops->fn_lock(tty);
	wait_entry_remove(&tty->wl, we);
	tty->ops->fn_unlock(tty);
}

static const struct filp_ops tty_file_ops = {
	.fn_read = &tty_read,
	.fn_write = &tty_write,
	.fn_ioctl = &tty_ioctl,
	.fn_poll = &tty_poll,
	.fn_poll_add = &tty_poll_add,
	.fn_poll_del = &tty_poll_del,
};

void tty_init(tty_filp *tty)
{
	init_fp(&tty->fp, &tty_file_ops);

	tty->tios.c_lflag = ICANON | ECHO;
	tty->tios.c_cc[VERASE] = 8;
	tty->tios.c_cc[VEOF] = 4;
	tty->tios.c_oflag = ONLCR | OPOST;
	tty->eof = 0;
	tty->ready_count = 0;
}
