/*
 * Console definitions
 *
 * Copyright (C)  2012 - 2013 Mike McCormack
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

#ifndef __TTY_H__
#define __TTY_H__

#include "linux-defines.h"

struct _tty_filp;

struct con_ops {
	void (*fn_lock)(struct _tty_filp *con);
	void (*fn_unlock)(struct _tty_filp *con);
	int (*fn_write)(struct _tty_filp *con, unsigned char ch);
	void (*fn_get_winsize)(struct _tty_filp *con, struct winsize *ws);
};

struct _tty_filp {
	filp fp;
	struct con_ops *ops;
	int eof;
	unsigned char ready_data[20];
	int ready_count;
	struct termios tios;
	struct wait_list wl;
};

typedef struct _tty_filp tty_filp;

void tty_input_add_string(tty_filp *con, const char *string);
void tty_input_add_char(tty_filp *con, char ch);
void tty_init(tty_filp* con);

#endif /* __TTY_H__ */
