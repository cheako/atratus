/*
 * Simple test to get the terminal size
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

#include <sys/ioctl.h>
#include <termios.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	struct winsize ws;

	if (0 != ioctl(0, TIOCGWINSZ, &ws))
		return 1;
	printf("Size: %dx%d\n", ws.ws_col, ws.ws_row);
	return 0;
}
