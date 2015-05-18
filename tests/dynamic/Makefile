# dynamically linked tests
#
# Copyright (C) 2012 Mike McCormack
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#

CFLAGS = -Wall -fno-stack-protector
CFLAGS = -Wall -O2
CC = gcc

TARGETS = \
	args \
	bsearch \
	ctype \
	dir \
	env \
	fork \
	futex \
	getopt \
	getopt_long \
	hw \
	inet \
	jmpbuf \
	ln \
	ls \
	malloc \
	mmap \
	pipe \
	qsort \
	read \
	socket \
	stat \
	stdio \
	stdlib \
	string \
	time \
	tls \
	ttysize \
	uname \
	vtplay

all: $(TARGETS)

# dynamicly linked with libc
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
