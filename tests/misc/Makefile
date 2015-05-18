
CFLAGS += -Wall -O2
CFLAGS += -m32

all: hw

hw: hw.o
	@echo lin32 cc
	@$(CC) -m32 -static -o $@ $<

clean:
	rm -f *.o hw
