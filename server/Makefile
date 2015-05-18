CFLAGS += -Wall -O2
CFLAGS += -fno-builtin
CFLAGS += -I../include
CFLAGS += -Wp,-MD,.$@.d -Wp,-MT,$@

MINGWCC = i586-mingw32msvc-gcc
NATIVEEXEFLAGS = -lntdll -nostartfiles -nodefaultlibs -Wl,--subsystem=native -e __entry

all: atratus.exe linux.exe

%.pe.o: %.c
	$(MINGWCC) -DNT $(CFLAGS) -c -o $@ $<

ATRATUS_SRCS = \
	atratus.c \
	dev.c \
	pipe.c \
	tty.c \
	vt100.c \
	winfs.c

STUB_SRCS = \
	linux.c

ATRATUS_OBJECTS = $(ATRATUS_SRCS:.c=.pe.o)
STUB_OBJECTS = $(STUB_SRCS:.c=.pe.o)

OBJECTS = $(ATRATUS_OBJECTS) $(STUB_OBJECTS)

-include $(OBJECTS:%=$(dir %).$(notdir %).d)

atratus.exe: $(ATRATUS_OBJECTS)
	$(MINGWCC) -o $@ $^ -lntdll -lkernel32 -lpsapi

# a stub called linux so the task manager shows something sensible
linux.exe: $(STUB_OBJECTS)
	$(MINGWCC) -static -o $@ $^ $(NATIVEEXEFLAGS)

clean:
	rm -f atratus.exe linux.exe *.pe.o *.pe.o.d
