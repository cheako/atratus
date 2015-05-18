# Server / core system call emulation and translation
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
CFLAGS += -Wall -O2
CFLAGS += -fno-builtin
CFLAGS += -I../include
CFLAGS += -Wp,-MD,.$@.d -Wp,-MT,$@

MINGWCC = i586-mingw32msvc-gcc
NATIVEEXEFLAGS = -lntdll -nostartfiles -nodefaultlibs -Wl,--subsystem=native -e __entry

all: atratus.exe cygsymlink.exe linux.exe

%.pe.o: %.c
	$(MINGWCC) -DNT $(CFLAGS) -c -o $@ $<

ATRATUS_SRCS = \
	atratus.c \
	debug.c \
	dev.c \
	elf.c \
	inet.c \
	null.c \
	pipe.c \
	ntstatus.c \
	tty.c \
	vm.c \
	vt100.c \
	winfs.c

STUB_SRCS = \
	linux.c

CYGSYMLINK_SRCS = \
	cygsymlink.c

ATRATUS_OBJECTS = $(ATRATUS_SRCS:.c=.pe.o)
STUB_OBJECTS = $(STUB_SRCS:.c=.pe.o)
CYGSYMLINK_OBJECTS = $(CYGSYMLINK_SRCS:.c=.pe.o)

OBJECTS = $(ATRATUS_OBJECTS) $(STUB_OBJECTS)

-include $(OBJECTS:%=$(dir %).$(notdir %).d)

atratus.exe: $(ATRATUS_OBJECTS)
	$(MINGWCC) -o $@ $^ -lntdll -lkernel32 -lpsapi -lws2_32

# a stub called linux so the task manager shows something sensible
linux.exe: $(STUB_OBJECTS)
	$(MINGWCC) -static -o $@ $^ $(NATIVEEXEFLAGS)

cygsymlink.exe: $(CYGSYMLINK_OBJECTS)
	$(MINGWCC) -static -o $@ $^ -lntdll -lkernel32

clean:
	rm -f atratus.exe cygsymlink.exe linux.exe *.pe.o .*.pe.o.d
