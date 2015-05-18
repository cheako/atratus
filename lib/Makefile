# C library and shared object loader
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

all:
CFLAGS = -Wall -fno-stack-protector
CC = gcc
CFLAGS = -Wall -O2
CFLAGS += -fno-stack-protector
CFLAGS += -fvisibility=hidden
CFLAGS += -I../include
CFLAGS += -fno-builtin-printf
CFLAGS += -fno-omit-frame-pointer
CFLAGS += -Wp,-MD,.$@.d -Wp,-MT,$@

LDFLAGS += -shared -Wl,-Bsymbolic -Wl,-Bsymbolic-functions
LDFLAGS += -Wl,--no-undefined -nostartfiles -nodefaultlibs
LDFLAGS += -fpic -g

all: ld-linux.so.2 libc.so.6 libm.so.6 libdl.so.2 librt.so.1 libpthread.so.0

LIBC_OBJECTS = \
	main.c

LIBM_OBJECTS = \
	main.c

LIBDL_OBJECTS = \
	main.c

LIBRT_OBJECTS = \
	main.c

LIBPTHREAD_OBJECTS = \
	main.c

LDSO_OBJECTS = \
	c.o \
	loader.o \
	stub.o

-include $(OBJECTS:%=$(dir %).$(notdir %).d)

ld-linux.so.2: $(LDSO_OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

libc.so.6: $(LIBC_OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

libm.so.6: $(LIBM_OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

libdl.so.2: $(LIBM_OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

librt.so.1: $(LIBRT_OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

libpthread.so.0: $(LIBPTHREAD_OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

clean:
	rm -f $(TARGET) *.o .*.o.d
