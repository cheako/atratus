CFLAGS = -Wall -O2
CC = gcc

TARGETS = \
	args \
	bsearch \
	dir \
	getopt \
	getopt_long \
	hw \
	malloc \
	stdio \
	stdlib \
	string \
	ttysize \
	uname

all: $(TARGETS)

# dynamicly linked with libc
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
