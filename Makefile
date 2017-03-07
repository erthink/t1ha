CC ?= cc
# LY: -march=native is a workaround for a GCC 4.x bug,
# which was fixed in 5.0 and later.
CFLAGS ?= -std=c99 -march=native -Wextra -Werror -O

SOURCES = test.c t1ha1.c t1ha0.c t1ha.h t1ha_bits.h Makefile

check: test
	./test

all: check32 check64

test: $(SOURCES)
	$(CC) $(CFLAGS) -DT1HA_TESTING -o $@ t1ha1.c t1ha0.c test.c

clean:
	rm -f test test32 test64

test32: $(SOURCES)
	$(CC) $(CFLAGS) -DT1HA_TESTING -m32 -o $@ t1ha1.c t1ha0.c test.c

check32: test32
	./test32

test64: $(SOURCES)
	$(CC) $(CFLAGS) -DT1HA_TESTING -m64 -o $@ t1ha1.c t1ha0.c test.c

check64: test64
	./test64
