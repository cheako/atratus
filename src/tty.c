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
#include "vm.h"
#include "tty.h"
#include "linux-errno.h"
#include "linux-defines.h"
#include "debug.h"

static void tty_poll_add(struct filp *f, struct wait_entry *we);
static void tty_poll_del(struct filp *f, struct wait_entry *we);
static int tty_write_output(struct tty_filp *tty, unsigned char ch);

static int tty_is_canonical(struct tty_filp *tty)
{
	return tty->tios.c_lflag & ICANON;
}

/*
 * Process input characters into an input string
 * return number of characters ready to read
 */
static int tty_process_input(struct tty_filp *tty)
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
		if (end < 0 && !tty->leader->ttyeof)
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
				tty->leader->ttyeof = 1;
			}
		}

		if (pos != i)
			tty->ready_data[pos] = ch;
		pos++;
	}

	tty->ready_count -= (i - pos);

	return end + 1;
}

static void tty_discard_input(struct tty_filp *tty)
{
	tty->ready_count = 0;
}

static int tty_read(struct filp *f, void *buf, user_size_t size, loff_t *ofs, int block)
{
	struct tty_filp *tty = (struct tty_filp*) f;
	int ret = 0;
	struct wait_entry we;
	int done = 0;

	we.p = current;
	tty_poll_add(&tty->fp, &we);

	while (ret < size && !tty->leader->ttyeof && !done && current->state == thread_ready)
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

			memcpy(buf, tty->ready_data, len);
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
			int r;

			r = process_pending_signal_check(current);
			if (r < 0)
			{
				if (!ret)
					r = ret;
				break;
			}

			schedule();
		}
	}

	tty_poll_del(&tty->fp, &we);

	dprintf("tty_read r = %d/%d\n", ret, size);

	return ret;
}

#define FROM_FIELD(type, ptr, field) \
	((type*)(((char*)(ptr)) - (uintptr_t)&(((type*)NULL)->field)))

void tty_check_signal(struct workitem *item)
{
	struct tty_filp *tty;

	tty = FROM_FIELD(struct tty_filp, item, interrupt_item);

	tty->ops->fn_lock(tty);
	item->fn = 0;
	if (tty->suspend)
		process_signal_group(tty->leader, _L(SIGTSTP));
	tty->suspend = 0;
	if (tty->interrupt)
		process_signal_group(tty->leader, _L(SIGINT));
	tty->interrupt = 0;
	tty->ops->fn_unlock(tty);
}

static uint8_t tty_control_echo[256] =
{
	1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,
};

void tty_input_add_char(struct tty_filp *tty, char ch)
{
	struct wait_entry *we;
	struct workitem *item = NULL;

	tty->ops->fn_lock(tty);

	if (ch == tty->tios.c_cc[VSUSP])
		tty->suspend++;
	else if (ch == tty->tios.c_cc[VINTR])
		tty->interrupt++;
	else if (tty->ready_count < sizeof tty->ready_data)
		tty->ready_data[tty->ready_count++] = ch;

	/* TODO: send only to the controlling terminal */
	LIST_FOR_EACH(&tty->wl, we, item)
		ready_list_add(we->p);

	if ((tty->suspend || tty->interrupt) &&
		!ELEMENT_IN_LIST(&tty->interrupt_item, item))
	{
		/* function pointer valid indicates pending */
		item = &(tty->interrupt_item);
		if (!item->fn)
			item->fn = tty_check_signal;
		else
			item = NULL;
	}

	if (tty->tios.c_lflag & ECHOCTL)
	{
		if (tty_control_echo[(uint8_t)ch])
		{
			tty_write_output(tty, '^');
			tty_write_output(tty, ch - 1 + 'A');
		}
	}

	if (tty->tios.c_lflag & ECHO)
	{
		tty_write_output(tty, ch);
	}

	tty->ops->fn_unlock(tty);

	if (item)
		work_add(item);
}

void tty_input_add_string(struct tty_filp *tty, const char *string)
{
	struct wait_entry *we;
	int len = strlen(string);

	tty->ops->fn_lock(tty);
	if ((tty->ready_count + len) <= sizeof tty->ready_data)
	{
		memcpy(&tty->ready_data[tty->ready_count], string, len);
		tty->ready_count += len;
	}

	LIST_FOR_EACH(&tty->wl, we, item)
		ready_list_add(we->p);

	tty->ops->fn_unlock(tty);
}

/* write to the terminal, observing termios settings */
static int tty_write_output(struct tty_filp *tty, unsigned char ch)
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

static int tty_write(struct filp *f, const void *buffer, user_size_t size, loff_t *off, int block)
{
	struct tty_filp *tty = (struct tty_filp*) f;
	DWORD written = 0;
	const unsigned char *p = buffer;
	int r, i;

	tty_debug_dump_buffer(buffer, size);

	for (i = 0; i < size; i++)
	{
		r = tty_write_output(tty, *p);
		if (r < 0)
			break;
		written++;
		p++;
	}

	dprintf("ret = %ld\n", written);

	return written;
}

static int tty_set_termios(struct tty_filp *tty, user_ptr_t p)
{
	int r;
	/*
	 * There's two or three different termios structures.
	 * TODO: use the kernel structure, not the libc one
	 */
	STATIC_ASSERT(sizeof tty->tios == 36);

	r = vm_memcpy_from_process(current, &tty->tios, p, sizeof tty->tios);
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

static int tty_get_termios(struct tty_filp *tty, user_ptr_t p)
{
	dprintf("get termios(%08x)\n", p);
	STATIC_ASSERT(sizeof tty->tios == 36);
	return vm_memcpy_to_process(current, p, &tty->tios, sizeof tty->tios);
}

static int tty_get_winsize(struct tty_filp *tty, user_ptr_t ptr)
{
	struct winsize ws;

	tty->ops->fn_get_winsize(tty, &ws);
	return vm_memcpy_to_process(current, ptr, &ws, sizeof ws);
}

static int tty_tcflush(struct tty_filp *tty, int what)
{
	return 0;
}

static int tty_get_process_group(struct tty_filp *tty, user_ptr_t ptr)
{
	int pgid = process_getpid(tty->leader);
	dprintf("TIOCGPGRP -> %d\n", pgid);
	return vm_memcpy_to_process(current, ptr, &pgid, sizeof pgid);
}

static int tty_set_process_group(struct tty_filp *tty, user_ptr_t ptr)
{
	struct process *p;
	int pgid;
	int r;

	dprintf("TIOCSPGRP -> %08x\n", ptr);

	r = vm_memcpy_from_process(current, &pgid, ptr, sizeof pgid);
	if (r < 0)
		return r;

	if (!current->tty)
		return -_L(ENOTTY);
	if (tty != (struct tty_filp*) current->tty)
		return -_L(ENOTTY);

	p = process_find(pgid);
	if (!p)
		return -_L(EINVAL);

	/* FIXME: refcount processes? */
	tty->leader = p;

	return 0;
}

static int tty_ioctl(struct filp *f, int cmd, unsigned long arg)
{
	struct tty_filp *tty = (struct tty_filp*) f;
	int r = 0;

	switch (cmd)
	{
	case TIOCGPGRP:
		return tty_get_process_group(tty, arg);
	case TIOCSPGRP:
		return tty_set_process_group(tty, arg);

	/*
	 * TODO: termios handling is wrong
	 *       Set calls do subtly different things.
	 */
	case TIOCS:
		return tty_set_termios(tty, arg);
	case TCSETSW:
		return tty_set_termios(tty, arg);
	case TCSETSF:	/* TODO: drain output */
		tty_discard_input(tty);
		return tty_set_termios(tty, arg);
	case TCSETAW:
		return tty_set_termios(tty, arg);
	case TIOCG:
		return tty_get_termios(tty, arg);
	case TIOCGWINSZ:
		return tty_get_winsize(tty, arg);
	case TCFLUSH:
		return tty_tcflush(tty, arg);
	default:
		dprintf("unknown tty ioctl(%08x, %08lx)\n", cmd, arg);
		r = -_L(EINVAL);
	}

	return r;
}

static int tty_poll(struct filp *f)
{
	int events = 0;
	struct tty_filp *tty = (struct tty_filp*) f;

	tty->ops->fn_lock(tty);
	if (0 != tty_process_input(tty))
		events |= _l_POLLIN;
	events |= _l_POLLOUT;
	tty->ops->fn_unlock(tty);
	return events;
}

static void tty_poll_add(struct filp *f, struct wait_entry *we)
{
	struct tty_filp *tty = (struct tty_filp*) f;

	tty->ops->fn_lock(tty);
	LIST_APPEND(&tty->wl, we, item);
	tty->ops->fn_unlock(tty);
}

static void tty_poll_del(struct filp *f, struct wait_entry *we)
{
	struct tty_filp *tty = (struct tty_filp*) f;

	tty->ops->fn_lock(tty);
	LIST_REMOVE(&tty->wl, we, item);
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

void tty_init(struct tty_filp *tty, struct process *leader)
{
	init_fp(&tty->fp, &tty_file_ops);

	tty->tios.c_lflag = ICANON | ECHO | ECHOCTL;
	tty->tios.c_cc[VINTR] = 3;
	tty->tios.c_cc[VERASE] = 8;
	tty->tios.c_cc[VEOF] = 4;
	tty->tios.c_cc[VSUSP] = 26;
	tty->tios.c_oflag = ONLCR | OPOST;
	tty->ready_count = 0;
	tty->leader = leader;
	LIST_ELEMENT_INIT(&tty->interrupt_item, item);
}
