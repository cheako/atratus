CC = gcc
CFLAGS = -Wall -O2
CFLAGS += -fno-stack-protector
CFLAGS += -fvisibility=hidden
CFLAGS += -I../include
CFLAGS += -fno-builtin-printf

LDFLAGS += -shared -Wl,-Bsymbolic -Wl,-Bsymbolic-functions
LDFLAGS += --no-undefined -nostartfiles -nodefaultlibs
LDFLAGS += -fpic -g

TARGET = ld-linux.so.2

$(TARGET): c.o loader.o stub.o subr_prf.o
	$(CC) -o $@ $(LDFLAGS) -e _start $^

clean:
	rm -f $(TARGET) *.o
