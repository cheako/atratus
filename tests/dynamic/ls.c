/*
 * Simple ls implementation for testing
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
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>

struct linux_dirent {
	long           d_ino;
	off_t          d_off;
	unsigned short d_reclen;
	char           d_name[];
};

int getdents(int fd, unsigned char *buf, size_t size)
{
	return syscall(SYS_getdents, fd, buf, size);
}

int main(int argc, char **argv)
{
	unsigned char buf[0x1000];
	int fd;
	int r;
	int n = 0;

	fd = open(".", O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr, "failed to open directory (%d)", errno);
		exit(1);
	}

	r = getdents(fd, (void*)buf, sizeof buf);

	while (n < r)
	{
		struct linux_dirent *de = (void*) &buf[n];

		printf("%.*s\n", strlen(de->d_name), de->d_name);
		if (de->d_reclen < sizeof *de)
			break;
		n += de->d_reclen;
	}

	close(fd);

	return 0;
}
