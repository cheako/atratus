
CFLAGS += -Wall -O2

all: hw

hw: hw.o
	$(CC) -static -o $@ $<

clean:
	rm -f *.o hw
