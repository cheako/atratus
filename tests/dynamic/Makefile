CFLAGS = -Wall -O2
CC = gcc

TARGETS = \
	args \
	bsearch \
	hw \
	strncmp

all: $(TARGETS)

# dynamicly linked with libc
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o
