/*
 * termios dump and interactive test
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>

int main(int argc, char **argv)
{
	char buf[0x100];
	int r, i;
	struct termios oldtios;

	printf("sizeof tios = %d\n", sizeof oldtios);
	printf("tios.c_cc = %d\n", (int)&((struct termios*)NULL)->c_cc[0]);

	r = tcgetattr(0, &oldtios);
	if (r < 0)
		return 1;

	printf("tios.c_iflag: (%08x) %s %s %s %s %s\n", oldtios.c_iflag,
		 (oldtios.c_iflag & ICRNL) ? "ICRNL" : "~ICRNL",
		 (oldtios.c_iflag & INLCR) ? "INLCR" : "~INLCR",
		 (oldtios.c_iflag & IUCLC) ? "IUCLC" : "~IUCLC",
		 (oldtios.c_iflag & IXON) ? "IXON" : "~IXON",
		 (oldtios.c_iflag & IXON) ? "IXOFF" : "~IXOFF");

	printf("tios.c_oflag: (%08x) %s %s %s %s %s\n", oldtios.c_oflag,
		 (oldtios.c_oflag & ONLRET) ? "ONLRET" : "~ONLRET",
		 (oldtios.c_oflag & OCRNL) ? "OCRNL" : "~OCRNL",
		 (oldtios.c_oflag & ONLCR) ? "ONLCR" : "~ONLCR",
		 (oldtios.c_oflag & OLCUC) ? "OLCUC" : "~OLCUC",
		 (oldtios.c_oflag & OPOST) ? "OPOST" : "~POST");

	printf("tios.c_lflag (%08x): %s %s\n", oldtios.c_lflag,
		 (oldtios.c_lflag & ECHO) ? "ECHO" : "~ECHO",
		 (oldtios.c_lflag & ICANON) ? "ICANON" : "~ICANON");

	if (argc < 2)
	{
		printf("Args are (can|raw)\n");
		return 1;
	}

	if (!strcmp(argv[1], "can"))
	{
		printf("Using canonical mode\n");
	}
	else if (!strcmp(argv[1], "can"))
	{
		struct termios tios;

		memset(&tios, 0, sizeof tios);

		r = tcgetattr(0, &tios);
		if (r < 0)
			return 1;

		tios.c_lflag &= ~ICANON;
		r = tcsetattr(0, 0, &tios);
		if (r < 0)
			return 1;
	}

	r = read(0, buf, sizeof buf);
	if (r > 0)
		r = write(1, buf, r);
	printf("read %d characters\n", r);
	for (i = 0; i < r; i++)
		printf("%02x ", buf[i]);
	printf("\n");
	/* restore */
	tcsetattr(0, 0, &oldtios);
	return 0;
}
