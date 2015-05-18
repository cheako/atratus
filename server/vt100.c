/*
 * vt100 terminal emulation in a windows console
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
#include "tty.h"
#include "vt100.h"

#define MAX_VT100_PARAMS 3

struct _vt100_filp
{
	con_filp con;
	int state;
	int num[MAX_VT100_PARAMS];
	int num_count;
	int fg_color;
	int bg_color;
	int brightness;
	int cursor_key_mode;
	HANDLE thread;
	HANDLE handle;
	CRITICAL_SECTION cs;
};

typedef struct _vt100_filp vt100_filp;

static int vt100_set_cursor_pos(vt100_filp *vt, int x, int y)
{
	COORD coord;
	CONSOLE_SCREEN_BUFFER_INFO info;
	DWORD height, width;
	BOOL r;

	dprintf("cursor to %d,%d\n", x, y);

	GetConsoleScreenBufferInfo(vt->handle, &info);
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
	r = SetConsoleCursorPosition(vt->handle, coord);
	if (!r)
		dprintf("failed to set cursor\n");
	return 0;
}

static DWORD vt100_get_attributes(vt100_filp *vt)
{
	DWORD dwAttribute = 0;

	if (vt->brightness)
		dwAttribute |= FOREGROUND_INTENSITY;

	switch (vt->fg_color)
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

	switch (vt->bg_color)
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

static int vt100_set_color(vt100_filp *vt)
{
	DWORD dwAttribute;
	int i;

	for (i = 0; i <= vt->num_count; i++)
	{
		int code = vt->num[i];

		if (code >= 30 && code <= 37)
			vt->fg_color = code;
		else if (code >= 40 && code <= 47)
			vt->bg_color = code;
		else if (code == 0)
		{
			vt->fg_color = 37;
			vt->bg_color = 40;
			vt->brightness = 0;
		}
		else if (code == 1)
			vt->brightness = code;
		else
			dprintf("Unhandled color code %d\n", code);
	}

	dwAttribute = vt100_get_attributes(vt);

	SetConsoleTextAttribute(vt->handle, dwAttribute);
	return 0;
}

/* carriage return.  Move the cursor to the start of the line */
static void vt100_do_cr(vt100_filp *vt)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD coord;

	GetConsoleScreenBufferInfo(vt->handle, &info);
	coord = info.dwCursorPosition;
	coord.X = 0;
	SetConsoleCursorPosition(vt->handle, coord);
}

/* line feed. Go down one line, but not to the start */
static void vt100_do_lf(vt100_filp *vt)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD coord;

	GetConsoleScreenBufferInfo(vt->handle, &info);
	coord = info.dwCursorPosition;
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
		ScrollConsoleScreenBuffer(vt->handle, &rect, NULL, topleft, &ci);
		dprintf("scrolled\n");
	}
	else
		coord.Y++;
	SetConsoleCursorPosition(vt->handle, coord);
}

static int vt100_write_normal(vt100_filp *vt, unsigned char ch)
{
	DWORD write_count = 0;
	BOOL r;

	switch (ch)
	{
	case 0x1b:
		vt->state = 1;
		break;
	case 0x0d:
		vt100_do_cr(vt);
		break;
	case 0x0a:
		vt100_do_lf(vt);
		break;
	default:
		r = WriteConsole(vt->handle, &ch, 1, &write_count, NULL);
		if (!r)
			return -_L(EIO);
	}

	return 0;
}

static int vt100_write_wait_first_char(vt100_filp *vt, unsigned char ch)
{
	int i;

	for (i = 0; i < MAX_VT100_PARAMS; i++)
		vt->num[i] = 0;
	vt->num_count = 0;

	switch (ch)
	{
	case '[':
		vt->state = 2;
		break;
	case '#':
		vt->state = 3;
		break;
	case '(':
		vt->state = 6;
		break;
	case ')':
		vt->state = 7;
		break;
	default:
		vt->state = 0;
	}

	return 0;
}

static void vt100_device_status(vt100_filp *vt, int req)
{
	char response[16];
	CONSOLE_SCREEN_BUFFER_INFO info;

	switch (req)
	{
	case 6: /* query cursor position */
		GetConsoleScreenBufferInfo(vt->handle, &info);
		sprintf(response, "\x1b[%d;%dR",
			info.dwCursorPosition.Y+1,
			info.dwCursorPosition.X+1);
		dprintf("response = %s\n", response+1);
		tty_input_add_string(&vt->con, response);
		break;
	case 5: /* query device status */
	default:
		dprintf("unknown request %d\n", req);
	}
}

static void vt100_erase_to_end_of_line(vt100_filp *vt)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD pos;
	DWORD count = 0;

	memset(&info, 0, sizeof info);

	if (!GetConsoleScreenBufferInfo(vt->handle, &info))
	{
		/* this happens if the handle is a file */
		dprintf("GetConsoleScreenBufferInfo() failed\n");
		return;
	}

	pos = info.dwCursorPosition;

	FillConsoleOutputCharacter(vt->handle, ' ',
		info.dwSize.X - pos.X, pos, &count);

	dprintf("erased %d at %hd,%hd\n", count, pos.X, pos.Y);

	SetConsoleCursorPosition(vt->handle, pos);
}

static void vt100_erase_screen(vt100_filp *vt, int n)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD pos, top;
	DWORD count;

	GetConsoleScreenBufferInfo(vt->handle, &info);

	pos = info.dwCursorPosition;
	top.X = 0;
	top.Y = 0;

	switch (n)
	{
	case 0:
		/* erase from cursor to end */
		FillConsoleOutputCharacter(vt->handle, ' ',
			(info.dwSize.Y - pos.Y) * info.dwSize.X +
			info.dwSize.X - pos.X, pos, &count);
		break;
	case 1:
		/* erase from top to cursor */
		FillConsoleOutputCharacter(vt->handle, ' ',
					pos.Y * info.dwSize.X + pos.X,
					top, &count);
		break;
	case 2:
		/* erase entire screen */
		SetConsoleCursorPosition(vt->handle, top);
		FillConsoleOutputCharacter(vt->handle, ' ',
					info.dwSize.Y * info.dwSize.X,
					top, &count);
		break;
	}

	SetConsoleCursorPosition(vt->handle, pos);
}

static void vt100_move_cursor(vt100_filp *vt, int delta_x, int delta_y)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD pos;

	GetConsoleScreenBufferInfo(vt->handle, &info);

	pos = info.dwCursorPosition;

	pos.X += delta_x;
	pos.Y += delta_y;

	if (pos.X < 0)
		pos.X = 0;
	if (pos.X >= info.dwSize.X)
		pos.X = info.dwSize.X - 1;
	if (pos.Y < 0)
		pos.Y = 0;
	if (pos.Y >= info.dwSize.Y)
		pos.Y = info.dwSize.Y - 1;

	SetConsoleCursorPosition(vt->handle, pos);
}


/*
 * wait for a double height/double width command
 * (These are probably not possible on a Windows console)
 */
static int vt100_write_wait_dhdw_mode(vt100_filp *vt, unsigned char ch)
{
	switch (ch)
	{
	case '8':	/* fill upper area of screen with E */
	case '3':	/* double height line, top half */
	case '4':	/* double height line, bottom half */
	case '5':	/* single line mode */
	case '6':	/* double line mode */
		break;
	}
	vt->state = 0;
	return 0;
}

static void vt_hide_cursor(vt100_filp *vt, int enable)
{
	CONSOLE_CURSOR_INFO cci;

	GetConsoleCursorInfo(vt->handle, &cci);
	cci.bVisible = enable;
	SetConsoleCursorInfo(vt->handle, &cci);
}

/*
 *  ESC [ ? N h  - enable mode N
 *  ESC [ ? N l  - disable mode N
 */
static int vt100_write_wait_mode_switch_num(vt100_filp *vt, unsigned char ch)
{
	int enable = 0;
	if (ch >= '0' && ch <= '9')
	{
		vt->num[0] *= 10;
		vt->num[0] += ch - '0';
		return 0;
	}
	else if (ch == 'h')
		enable = 1;
	else if (ch == 'l')
		enable = 0;
	else
	{
		vt->state = 0;
		return 0;
	}

	dprintf("switch mode %d %s\n", vt->num[0], enable ? "on" : "off");

	switch (vt->num[0])
	{
	case 1:	/* cursor key mode */
		vt->cursor_key_mode = enable;
		break;
	case 2:	/* vt52/ANSI mode */
		break;
	case 3:	/* 132 column mode: 132/80 */
		break;
	case 4:	/* scrolling mode: smooth/jump */
		break;
	case 5:	/* screen: reverse/normal */
		break;
	case 6:	/* origin relative/absolute */
		break;
	case 7:	/* wraparound on/off */
		break;
	case 8:	/* autorepeat on/off */
		break;
	case 9:	/* interlace on/off */
		break;
	case 25:
		vt_hide_cursor(vt, enable);
		break;
	default:
		break;
	}
	vt->state = 0;
	return 0;
}

static int vt100_write_wait_char_set_g0(vt100_filp *vt, unsigned char ch)
{
	dprintf("switch to g0 %c - unsupported\n", ch);
	vt->state = 0;
	return 0;
}

static int vt100_write_wait_char_set_g1(vt100_filp *vt, unsigned char ch)
{
	dprintf("switch to g1 %c - unsupported\n", ch);
	vt->state = 0;
	return 0;
}

static int vt100_write_wait_number(vt100_filp *vt, unsigned char ch)
{
	switch (ch)
	{
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		vt->num[vt->num_count] *= 10;
		vt->num[vt->num_count] += (ch - '0');
		break;
	case ';':
		vt->num_count++;
		if (vt->num_count >= MAX_VT100_PARAMS)
		{
			dprintf("too many tty params\n", ch);
			vt->state = 0;
		}
		break;
	case 'm':
		vt100_set_color(vt);
		vt->state = 0;
		break;
	case 'n':
		vt100_device_status(vt, vt->num[0]);
		vt->state = 0;
		break;
	case 'A':
		if (!vt->num[0])
			vt->num[0]++;
		vt100_move_cursor(vt, 0, -vt->num[0]);
		vt->state = 0;
		break;
	case 'B':
		if (!vt->num[0])
			vt->num[0]++;
		vt100_move_cursor(vt, 0, vt->num[0]);
		vt->state = 0;
		break;
	case 'C':
		if (!vt->num[0])
			vt->num[0]++;
		vt100_move_cursor(vt, vt->num[0], 0);
		vt->state = 0;
		break;
	case 'D':
		if (!vt->num[0])
			vt->num[0]++;
		vt100_move_cursor(vt, -vt->num[0], 0);
		vt->state = 0;
		break;
	case 'K':
		vt100_erase_to_end_of_line(vt);
		vt->state = 0;
		break;
	case 'J':
		vt100_erase_screen(vt, vt->num[0]);
		vt->state = 0;
		break;
	case 'H':
		vt100_set_cursor_pos(vt, vt->num[1], vt->num[0]);
		vt->state = 0;
		break;
	case '?':
		vt->state = 4;
		break;
	default:
		dprintf("unknown escape code %c (num1)\n", ch);
		vt->state = 0;
	}
	return 0;
}

typedef int (*vt100_state_fn)(vt100_filp *vt, unsigned char ch);

static vt100_state_fn vt100_state_list[] = {
	vt100_write_normal,
	vt100_write_wait_first_char,
	vt100_write_wait_number,
	vt100_write_wait_dhdw_mode,
	vt100_write_wait_mode_switch_num,
	NULL,
	vt100_write_wait_char_set_g0,
	vt100_write_wait_char_set_g1,
};

static int vt100_write(con_filp *con, unsigned char ch)
{
	vt100_filp *vt = (void*) con;
	return vt100_state_list[vt->state](vt, ch);
}

static void vt100_send_cursor_code(vt100_filp *vt, char ch)
{
	char cursor[4] = { '\033', vt->cursor_key_mode ? '[' : 'O', ch, 0 };
	tty_input_add_string(&vt->con, cursor);
}

static DWORD WINAPI vt100_input_thread(LPVOID param)
{
	HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
	vt100_filp *vt = param;
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
			tty_input_add_char(&vt->con, '\n');
			break;
		case VK_UP:
			vt100_send_cursor_code(vt, 'A');
			break;
		case VK_DOWN:
			vt100_send_cursor_code(vt, 'B');
			break;
		case VK_RIGHT:
			vt100_send_cursor_code(vt, 'C');
			break;
		case VK_LEFT:
			vt100_send_cursor_code(vt, 'D');
			break;
		default:
			ch = ir.Event.KeyEvent.uChar.AsciiChar;
			if (ch)
				tty_input_add_char(&vt->con, ch);
			break;
		}

	}

	fprintf(stderr, "\ninput thread died\n");

	return 0;
}

static void vt100_get_winsize(con_filp *con, struct winsize *ws)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	vt100_filp *vt= (void*) con;

	GetConsoleScreenBufferInfo(vt->handle, &info);

	ws->ws_col = info.srWindow.Right - info.srWindow.Left + 1;
	ws->ws_row = info.srWindow.Bottom - info.srWindow.Top + 1;
	ws->ws_xpixel = 0;
	ws->ws_ypixel = 0;

	dprintf("winsize -> %d,%d\n", ws->ws_col, ws->ws_row);
}

static void vt100_lock(con_filp *con)
{
	vt100_filp *vt= (void*) con;
	EnterCriticalSection(&vt->cs);
}

static void vt100_unlock(con_filp *con)
{
	vt100_filp *vt= (void*) con;
	LeaveCriticalSection(&vt->cs);
}

struct con_ops vt100_ops = {
	.fn_lock = vt100_lock,
	.fn_unlock = vt100_unlock,
	.fn_write = vt100_write,
	.fn_get_winsize = vt100_get_winsize,
};

static filp* alloc_vt100_console(HANDLE handle)
{
	vt100_filp *vt;
	con_filp *con;
	DWORD id;

	vt = malloc(sizeof *vt);
	if (!vt)
		return NULL;
	memset(vt, 0, sizeof *vt);
	con = &vt->con;

	con->ops = &vt100_ops;

	tty_init(con);

	vt->state = 0;
	vt->num_count = 0;
	vt->fg_color = 37;
	vt->bg_color = 40;
	vt->brightness = 0;
	vt->handle = handle;
	vt->cursor_key_mode = 1;

	SetConsoleMode(handle, ENABLE_PROCESSED_INPUT);

	InitializeCriticalSection(&vt->cs);

	vt->thread = CreateThread(NULL, 0, &vt100_input_thread, con, 0, &id);

	return &con->fp;
}

static filp *condev;

filp* get_vt100_console(HANDLE console)
{
	if (!condev)
		condev = alloc_vt100_console(console);
	return condev;
}
