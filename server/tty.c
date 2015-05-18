/*
 * atratus - Linux binary emulation for Windows
 *
 * Copyright (C)  2006-2012 Mike McCormack
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

typedef struct _con_filp con_filp;

typedef void *(*con_callback_fn)(void *param);

struct con_callback {
	con_callback_fn fn;
	void *param;
	struct con_callback *next;
};

#define MAX_VT100_PARAMS 3

struct termios
{
	unsigned int c_iflag;
	unsigned int c_oflag;
	unsigned int c_cflag;
	unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[8];
};

#define ICANON 2

struct _con_filp {
	filp fp;
	int state;
	int num[MAX_VT100_PARAMS];
	int num_count;
	int fg_color;
	int bg_color;
	int brightness;
	int ready_count;
	struct termios tios;
	int eof;
	unsigned char ready_data[20];
	struct wait_list wl;
	HANDLE thread;
	CRITICAL_SECTION cs;
};

/* vt100 emulation */

void con_poll_add(filp *f, struct wait_entry *we);
void con_poll_del(filp *f, struct wait_entry *we);

static int con_is_canonical(con_filp *con)
{
	return con->tios.c_lflag & ICANON;
}

int con_input_available(con_filp *con)
{
	int i;
	int r = 0;

	if (!con_is_canonical(con))
		r = (con->ready_count > 0);
	else
	{
		for (i = 0; r == 0 && i < con->ready_count; i++)
			if (con->ready_data[i] == '\r')
				r = 1;
	}

	dprintf("input available = %d\n", r);

	return r;
}

int con_read(filp *f, void *buf, size_t size, loff_t *ofs)
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

		EnterCriticalSection(&con->cs);
		assert(con->ready_count >= 0);
		if (con_input_available(con))
		{
			BYTE ch = con->ready_data[0];

			/* FIXME: use a ring buffer */
			con->ready_count--;
			memmove(con->ready_data, con->ready_data+1, con->ready_count);

			dprintf("tty read '%c'\n", ch);

			/* eof? */
			if (ch == 0x04)
				con->eof = 1;
			else
			{
				int r;
				r = current->ops->memcpy_to(buf, &ch, 1);
				if (r < 0)
				{
					if (ret > 0)
						break;
					return -_L(EFAULT);
				}
				buf = (char*)buf + 1;
				ret++;
			}
			if (con_is_canonical(con) && ch == '\r')
				done = 1;
		}
		else
		{
			wait = 1;
		}
		LeaveCriticalSection(&con->cs);

		if (wait)
		{
			current->state = thread_stopped;
			yield();
			current->state = thread_running;
		}
	}

	con_poll_del(&con->fp, &we);

	dprintf("r = %d\n", ret);

	return ret;
}

void tty_input_add_char(con_filp *con, char ch)
{
	EnterCriticalSection(&con->cs);

	if (con_is_canonical(con))
	{
		// backspace
		if (con->ready_count > 0 && ch == 9)
		{
			con->ready_count--;
		}
	}

	/* notify data is present */
	if (!con_input_available(con))
	{
		struct wait_entry *we;

		for (we = con->wl.head; we; we = we->next)
		{
			ready_list_add(we->p);
		}
	}

	/* add data to buffer */
	if (con->ready_count < sizeof con->ready_data)
		con->ready_data[con->ready_count++] = ch;

	dprintf("added '%c' to buffer\n", ch);
	LeaveCriticalSection(&con->cs);
}

void tty_input_add_string(con_filp *con, const char *string)
{
	int n = 0;

	EnterCriticalSection(&con->cs);
	while (string[n])
	{
		tty_input_add_char(con, string[n]);
		n++;
	}
	LeaveCriticalSection(&con->cs);
}

int tty_set_cursor_pos(con_filp *con, int x, int y)
{
	COORD coord;
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD height, width;
	BOOL r;

	dprintf("cursor to %d,%d\n", x, y);

	GetConsoleScreenBufferInfo(handle, &info);
	dprintf("dwSize %d,%d\n", info.dwSize.X, info.dwSize.Y);
	dprintf("srWindow %d,%d-%d,%d\n",
		info.srWindow.Left, info.srWindow.Top,
		info.srWindow.Right, info.srWindow.Bottom);
	height = info.srWindow.Bottom - info.srWindow.Top + 1;
	width = info.srWindow.Right - info.srWindow.Left + 1;
	if (x >= width)
		x = width;
	if (y >= height)
		y = height;
	if (y < 1)
		y = 1;
	if (x < 1)
		x = 1;
	coord.X = x - 1;
	coord.Y = y - 1;
	dprintf("Set %d,%d\n", coord.X, coord.Y);
	r = SetConsoleCursorPosition(handle, coord);
	if (!r)
		dprintf("failed to set cursor\n");
	return 0;
}

static DWORD tty_get_attributes(con_filp *con)
{
	DWORD dwAttribute = 0;

	if (con->brightness)
		dwAttribute |= FOREGROUND_INTENSITY;

	switch (con->fg_color)
	{
	case 30: /* Black */
		break;
	case 31: /* Red */
		dwAttribute |= FOREGROUND_RED;
		break;
	case 32: /* Green */
		dwAttribute |= FOREGROUND_GREEN;
		break;
	case 33: /* Yellow */
		dwAttribute |= FOREGROUND_RED | FOREGROUND_GREEN;
		break;
	case 34: /* Blue */
		dwAttribute |= FOREGROUND_BLUE;
		break;
	case 35: /* Magenta */
		dwAttribute |= FOREGROUND_RED | FOREGROUND_BLUE;
		break;
	case 36: /* Cyan */
		dwAttribute |= FOREGROUND_GREEN | FOREGROUND_BLUE;
		break;
	case 37: /* White */
		dwAttribute |= FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED;
		break;
	}

	switch (con->bg_color)
	{
	case 40: /* Black */
		break;
	case 41: /* Red */
		dwAttribute |= BACKGROUND_RED;
		break;
	case 42: /* Green */
		dwAttribute |= BACKGROUND_GREEN;
		break;
	case 43: /* Yellow */
		dwAttribute |= BACKGROUND_RED | BACKGROUND_GREEN;
		break;
	case 44: /* Blue */
		dwAttribute |= BACKGROUND_BLUE;
		break;
	case 45: /* Magenta */
		dwAttribute |= BACKGROUND_RED | BACKGROUND_BLUE;
		break;
	case 46: /* Cyan */
		dwAttribute |= BACKGROUND_GREEN | BACKGROUND_BLUE;
		break;
	case 47: /* White */
		dwAttribute |= BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED;
		break;
	}

	return dwAttribute;
}

int tty_set_color(con_filp *con, int code)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwAttribute;

	if (code >= 30 && code <= 37)
		con->fg_color = code;
	if (code >= 40 && code <= 47)
		con->bg_color = code;
	if (code >= 0 && code <= 1)
		con->brightness = code;

	dwAttribute = tty_get_attributes(con);

	SetConsoleTextAttribute(handle, dwAttribute);
	return 0;
}

void tty_do_cr(con_filp *con)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD coord;

	GetConsoleScreenBufferInfo(handle, &info);
	coord = info.dwCursorPosition;
	coord.X = 0;
	SetConsoleCursorPosition(handle, coord);
}

void tty_do_lf(con_filp *con)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD coord;

	GetConsoleScreenBufferInfo(handle, &info);
	coord = info.dwCursorPosition;
	if (1)
		coord.X = 0;
	if (coord.Y >= info.srWindow.Bottom)
	{
		SMALL_RECT rect;
		COORD topleft;
		CHAR_INFO ci;

		topleft.X = info.srWindow.Left;
		topleft.Y = info.srWindow.Top - 1;
		rect = info.srWindow;
		ci.Char.AsciiChar = ' ';
		ci.Attributes = 0;
		ScrollConsoleScreenBuffer(handle, &rect, NULL, topleft, &ci);
	}
	else
		coord.Y++;
	SetConsoleCursorPosition(handle, coord);
}

int tty_write_normal(con_filp *con, unsigned char ch)
{
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD write_count = 0;
	BOOL r;

	switch (ch)
	{
	case 0x1b:
		con->state = 1;
		break;
	case '\r':
		tty_do_cr(con);
		break;
#if 0
	case '\n':
		tty_do_lf(con);
		break;
#endif
	default:
		r = WriteConsole(handle, &ch, 1, &write_count, NULL);
		if (!r)
			return -_L(EIO);
	}

	return 0;
}

int tty_write_wait_lbracket(con_filp *con, unsigned char ch)
{
	if (ch == '[')
	{
		int i;

		con->state = 2;
		for (i=0; i<MAX_VT100_PARAMS; i++)
			con->num[i] = 0;
		con->num_count = 0;
	}
	else
		con->state = 0;

	return 0;
}

void tty_device_status(con_filp *con, int req)
{
	char response[16];
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);

	switch (req)
	{
	case 6: /* query cursor position */
		GetConsoleScreenBufferInfo(handle, &info);
		sprintf(response, "\x1b[%d;%dR",
			info.dwCursorPosition.Y+1,
			info.dwCursorPosition.X+1);
		dprintf("response = %s\n", response+1);
		tty_input_add_string(con, response);
		break;
	case 5: /* query device status */
	default:
		dprintf("unknown request %d\n", req);
	}
}

void tty_erase_to_end_of_line(con_filp *con)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD pos;
	DWORD count;

	GetConsoleScreenBufferInfo(handle, &info);

	pos = info.dwCursorPosition;

	dprintf("erasing at %d,%d\n", pos.X, pos.Y);

	FillConsoleOutputCharacter(handle, ' ',
		info.dwSize.X - pos.X, pos, &count);

	SetConsoleCursorPosition(handle, pos);
}

void tty_erase_to_end_of_screen(con_filp *con)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD pos;
	DWORD count;

	GetConsoleScreenBufferInfo(handle, &info);

	pos = info.dwCursorPosition;

	FillConsoleOutputCharacter(handle, ' ',
		(info.dwSize.Y - pos.Y) * info.dwSize.X +
		info.dwSize.X - pos.X, pos, &count);

	SetConsoleCursorPosition(handle, pos);
}

void tty_move_cursor(con_filp *con, int delta_x, int delta_y)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD pos;

	GetConsoleScreenBufferInfo(handle, &info);

	pos = info.dwCursorPosition;

	if (pos.X > 0 && pos.X < info.dwSize.X)
		pos.X += delta_x;
	if (pos.Y > 0 && pos.X < info.dwSize.Y)
		pos.Y += delta_y;

	SetConsoleCursorPosition(handle, pos);
}

int tty_write_wait_number(con_filp *con, unsigned char ch)
{
	switch (ch)
	{
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		con->num[con->num_count] *= 10;
		con->num[con->num_count] += (ch - '0');
		break;
	case ';':
		con->num_count++;
		if (con->num_count >= MAX_VT100_PARAMS)
		{
			dprintf("too many tty params\n", ch);
			con->state = 0;
		}
		break;
	case 'm':
		tty_set_color(con, con->num[0]);
		con->state = 0;
		break;
	case 'n':
		tty_device_status(con, con->num[0]);
		con->state = 0;
		break;
	case 'A':
		tty_move_cursor(con, 0, -con->num[0]);
		break;
	case 'B':
		tty_move_cursor(con, 0, con->num[0]);
		break;
	case 'C':
		tty_move_cursor(con, -con->num[0], 0);
		break;
	case 'D':
		tty_move_cursor(con, con->num[0], 0);
		break;
	case 'K':
		tty_erase_to_end_of_line(con);
		con->state = 0;
		break;
	case 'J':
		tty_erase_to_end_of_screen(con);
		con->state = 0;
		break;
	case 'H':
		tty_set_cursor_pos(con, con->num[1], con->num[0]);
		con->state = 0;
		break;
	default:
		dprintf("unknown escape code %c (num1)\n", ch);
		con->state = 0;
	}
	return 0;
}

typedef int (*tty_state_fn)(con_filp *con, unsigned char ch);

tty_state_fn tty_state_list[] = {
	tty_write_normal,
	tty_write_wait_lbracket,
	tty_write_wait_number,
};

int con_write(filp *f, const void *buf, size_t size, loff_t *off)
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
			buf_remaining = r;
			buf = (char*)buf + buf_remaining;
			p = buffer;
		}
		if (buf_remaining == 0)
			break;
		r = tty_state_list[con->state](con, *p);
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
	dprintf("set termios(%p)\n", p);
	return current->ops->memcpy_from(&con->tios, p, sizeof con->tios);
}

static int con_get_termios(con_filp *con, void *p)
{
	dprintf("get termios(%p)\n", p);
	return current->ops->memcpy_to(p, &con->tios, sizeof con->tios);
}

#define TIOCGPGRP  0x540F
#define TIOCSPGRP  0x5410
#define TIOCGWINSZ 0x5413

#define TIOCG     0x5401
#define TIOCS     0x5402

struct winsize {
	unsigned short	ws_row;
	unsigned short	ws_col;
	unsigned short	ws_xpixel;
	unsigned short	ws_ypixel;
};

static int con_get_winsize(void *ptr)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	struct winsize ws;
	int r;

	GetConsoleScreenBufferInfo(handle, &info);

	ws.ws_col = info.srWindow.Right - info.srWindow.Left + 1;
	ws.ws_row = info.srWindow.Bottom - info.srWindow.Top + 1;
	ws.ws_xpixel = 0;
	ws.ws_ypixel = 0;

	dprintf("winsize -> %d,%d\n", ws.ws_col, ws.ws_row);

	r = current->ops->memcpy_to(ptr, &ws, sizeof ws);
	if (r < 0)
		return r;

	return 0;
}

int con_ioctl(filp *f, int cmd, unsigned long arg)
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
		return con_get_winsize((void*)arg);
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
	EnterCriticalSection(&con->cs);
	if (con_input_available(con))
		events |= _l_POLLIN;
	events |= _l_POLLOUT;
	LeaveCriticalSection(&con->cs);
	return events;
}

void con_poll_add(filp *f, struct wait_entry *we)
{
	con_filp *con = (con_filp*) f;

	EnterCriticalSection(&con->cs);
	wait_entry_append(&con->wl, we);
	LeaveCriticalSection(&con->cs);
}

void con_poll_del(filp *f, struct wait_entry *we)
{
	con_filp *con = (con_filp*) f;

	EnterCriticalSection(&con->cs);
	wait_entry_remove(&con->wl, we);
	LeaveCriticalSection(&con->cs);
}

DWORD WINAPI con_input_thread(LPVOID param)
{
	HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
	con_filp *con = param;
	unsigned char ch = 0;
	DWORD count = 0;
	BOOL r;
	INPUT_RECORD ir;

	while (1)
	{
		r = ReadConsoleInput(in, &ir, 1, &count);
		if (!r)
		{
			fprintf(stderr, "\nReadConsoleInput failed\n");
			break;
		}
		if (!count)
			break;

		if (ir.EventType != KEY_EVENT)
			continue;

		if (!ir.Event.KeyEvent.bKeyDown)
			continue;

		switch (ir.Event.KeyEvent.wVirtualKeyCode)
		{
		case VK_RETURN:
			ch = '\r';
			break;
		default:
			ch = ir.Event.KeyEvent.uChar.AsciiChar;
		}

		if (!ch)
			continue;

		tty_input_add_char(con, ch);
	}

	fprintf(stderr, "\ninput thread died\n");

	return 0;
}

static const struct filp_ops con_file_ops = {
	.fn_read = &con_read,
	.fn_write = &con_write,
	.fn_ioctl = &con_ioctl,
	.fn_poll = &con_poll,
	.fn_poll_add = &con_poll_add,
	.fn_poll_del = &con_poll_del,
};

static filp* alloc_console(void)
{
	HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
	DWORD id = 0;
	con_filp *con;

	con = malloc(sizeof *con);

	memset(con, 0, sizeof *con);

	con->fp.ops = &con_file_ops;
	con->fp.handle = NULL;
	con->fp.pgid = 0;
	con->fp.poll_first = NULL;

	con->fp.pgid = 0;
	con->state = 0;
	con->num_count = 0;
	con->fg_color = 37;
	con->bg_color = 40;
	con->brightness = 0;
	con->ready_count = 0;
	con->eof = 0;
	con->tios.c_lflag |= ICANON;

	SetConsoleMode(in, ENABLE_PROCESSED_INPUT);

	InitializeCriticalSection(&con->cs);

	con->thread = CreateThread(NULL, 0, &con_input_thread, con, 0, &id);

	return &con->fp;
}

static filp *condev;

filp* get_console(void)
{
	if (!condev)
		condev = alloc_console();
	return condev;
}
