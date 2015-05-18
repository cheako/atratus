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

TARGET = ld-linux.so.2

all: $(TARGET)

OBJECTS = \
	c.o \
	loader.o \
	stub.o

-include $(OBJECTS:%=$(dir %).$(notdir %).d)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $(LDFLAGS) -e _start $^

clean:
	rm -f $(TARGET) *.o .*.o.d
