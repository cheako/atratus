CFLAGS = -Wall -O2
CC = gcc

TARGETS = \
	args \
	bsearch \
	getopt \
	getopt_long \
	hw \
	malloc \
	stdio \
	string \
	strtoul \
	uname

all: $(TARGETS)

# dynamicly linked with libc
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
