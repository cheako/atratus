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

MWCFLAGS += -Wall -fno-stack-protector
MWCFLAGS += -Wall -O2
MWCFLAGS += -fno-builtin
MWCFLAGS += -I../include
MWCFLAGS += -Wp,-MD,.$@.d -Wp,-MT,$@

have_ming32 := $(shell i586-mingw32msvc-gcc -v 2> /dev/null ; echo $$?)
have_ming64 := $(shell x86_64-w64-mingw32-gcc -v 2> /dev/null ; echo $$?)

MWCFLAGS32 += $(MWCFLAGS)
MWCFLAGS32 += -m32
MINGWCC32 = i586-mingw32msvc-gcc
WINDRES32 = i586-mingw32msvc-windres
NATIVEEXEFLAGS32 = -lntdll -nostartfiles -nodefaultlibs -Wl,--subsystem=native -e _entry

MWCFLAGS64 += $(MWCFLAGS)
MINGWCC64 = x86_64-w64-mingw32-gcc
WINDRES64 = x86_64-w64-mingw32-windres
NATIVEEXEFLAGS64 = -lntdll -nostartfiles -nodefaultlibs -Wl,--subsystem=native -e _entry

TARGETS := cygsymlink.exe linux.exe

ifeq ($(have_ming32),0)
TARGETS += atratus.exe
endif

ifeq ($(have_ming64),0)
TARGETS += atratus64.exe
endif

all: $(TARGETS)

%.pe32.o: %.c
	@echo win32 cc $<
	@$(MINGWCC32) -DNT $(MWCFLAGS32) -c -o $@ $<

%.pe64.o: %.c
	@echo win64 cc $<
	@$(MINGWCC64) -DNT $(MWCFLAGS64) -c -o $@ $<

ATRATUS_SRCS = \
	atratus.c \
	debug.c \
	dev.c \
	elf.c \
	emulate.c \
	inet.c \
	ntstatus.c \
	null.c \
	pipe.c \
	proc.c \
	random.c \
	tty.c \
	vm.c \
	vt100.c \
	winfs.c \
	zero.c

STUB_SRCS = \
	linux.c

CYGSYMLINK_SRCS = \
	cygsymlink.c

ATRATUS32_OBJECTS = $(ATRATUS_SRCS:.c=.pe32.o)
ATRATUS64_OBJECTS = $(ATRATUS_SRCS:.c=.pe64.o)
STUB_OBJECTS = $(STUB_SRCS:.c=.pe32.o)
CYGSYMLINK_OBJECTS = $(CYGSYMLINK_SRCS:.c=.pe32.o)

OBJECTS = $(ATRATUS32_OBJECTS) $(ATRATUS64_OBJECTS) $(STUB_OBJECTS) $(CYGSYMLINK_OBJECTS)

-include $(OBJECTS:%=$(dir %).$(notdir %).d)

%64.res: %.rc
	@echo win64 wr $<
	@$(WINDRES64) -i $< -o $@ -O coff

%32.res: %.rc
	@echo win32 wr $<
	@$(WINDRES32) -i $< -o $@ -O coff

atratus.exe: $(ATRATUS32_OBJECTS) atratus32.res
	@echo win32 ld $@
	@$(MINGWCC32) -o $@ $^ -lntdll -lkernel32 -lpsapi -lws2_32 -liphlpapi

atratus64.exe: $(ATRATUS64_OBJECTS) atratus64.res
	@echo win64 ld $@
	@$(MINGWCC64) -o $@ $^ -lntdll -lkernel32 -lpsapi -lws2_32 -liphlpapi


# a stub called linux so the task manager shows something sensible
linux.exe: $(STUB_OBJECTS)
	@echo win32 ld $@
	@$(MINGWCC32) -static -o $@ $^ $(NATIVEEXEFLAGS32)

cygsymlink.exe: $(CYGSYMLINK_OBJECTS)
	@echo win32 ld $@
	@$(MINGWCC32) -static -o $@ $^ -lntdll -lkernel32

clean:
	@echo clean
	@rm -f $(TARGETS) $(OBJECTS) .*.o.d *.res
