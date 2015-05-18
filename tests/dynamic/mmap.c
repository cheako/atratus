/*
 * mmap test
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
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int fd, r;
	off_t sz;
	void *p;

	if (argc < 2)
	{
		fprintf(stderr, "%s [file] - cats a file using mmap\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
	{
		fprintf(stderr, "open() failed\n");
		return 1;
	}

	sz = lseek(fd, 0, SEEK_END);
	if (sz == (off_t) -1)
	{
		fprintf(stderr, "lseek() failed\n");
		return 1;
	}

	p = mmap(0, sz, PROT_READ, 0, fd, 0);
	if (p == (void*) -1)
	{
		fprintf(stderr, "mmap() failed\n");
		return 1;
	}

	r = write(1, p, sz);
	if (r < 0)
	{
		fprintf(stderr, "write() failed\n");
		return 1;
	}

	close(fd);

	return 0;
}
