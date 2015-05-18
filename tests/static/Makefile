CFLAGS = -Wall -fno-stack-protector
CC = gcc

TARGETS = \
	args \
	brk \
	cat \
	date \
	dir \
	echo \
	exec \
	exit \
	fork \
	gettimeofday \
	gs \
	hw \
	mmap \
	pipe \
	select \
	sleep \
	stack \
	stat \
	stat64 \
	uname

all: $(TARGETS)

# no libc
%: %.c
	$(CC) $(CFLAGS) -o $@ -static -nostartfiles -nodefaultlibs $<

clean:
	rm -f $(TARGETS) *.o
