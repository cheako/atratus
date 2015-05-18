CFLAGS = -Wall -O2
CC = gcc

TARGETS = \
	args \
	bsearch \
	ctype \
	dir \
	fork \
	getopt \
	getopt_long \
	hw \
	jmpbuf \
	malloc \
	pipe \
	qsort \
	read \
	stat \
	stdio \
	stdlib \
	string \
	ttysize \
	uname \
	vtplay

all: $(TARGETS)

# dynamicly linked with libc
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
