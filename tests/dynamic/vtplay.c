/*
 * Cat a file slowly to a terminal
 * Good for testing terminal with files from:
 *
 * http://artscene.textfiles.com/vt100
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
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

int main(int argc, char **argv)
{
	char buf[10];
	int fd, r;

	if (argc != 2)
	{
		fprintf(stderr, "What, no files?\n");
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		return 1;
	while (1)
	{
		r = read(fd, buf, 1);
		if (r != 1)
			break;
		r = write(1, buf, 1);
		if (r != 1)
			break;
		poll(0, 0, 10);
	}
	close(fd);
	return 0;
}
