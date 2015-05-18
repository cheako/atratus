CFLAGS = -Wall -fno-stack-protector
CC = gcc

TARGETS = \
	args \
	cat \
	date \
	dir \
	echo \
	exec \
	exit \
	fork \
	gs \
	hw \
	mmap \
	pipe \
	sleep \
	stack \
	uname

all: $(TARGETS)

# no libc
%: %.c
	$(CC) $(CFLAGS) -o $@ -static -nostartfiles -nodefaultlibs $<

clean:
	rm -f $(TARGETS) *.o
