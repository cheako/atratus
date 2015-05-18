CFLAGS += -Wall -O2
CFLAGS += -fno-builtin
CFLAGS += -I../include
MINGWCC = i586-mingw32msvc-gcc
NATIVEEXEFLAGS = -lntdll -nostartfiles -nodefaultlibs -Wl,--subsystem=native -e __entry

all: atratus.exe linux.exe

%.pe.o: %.c
	$(MINGWCC) -DNT $(CFLAGS) -c -o $@ $<

atratus.exe: atratus.pe.o pipe.pe.o tty.pe.o
	$(MINGWCC) -o $@ $^ -lntdll -lkernel32 -lpsapi

# a stub called linux so the task manager shows something sensible
linux.exe: linux.pe.o
	$(MINGWCC) -static -o $@ $^ $(NATIVEEXEFLAGS)

clean:
	rm -f atratus.exe linux.exe *.pe.o
