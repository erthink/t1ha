CC ?= cc
# LY: -march=native is a workaround for a GCC 4.x bug,
# which was fixed in 5.0 and later.
CFLAGS ?= -std=c99 -march=native -Wextra -Werror -O

SOURCES = t1ha.h tests/main.c $(addprefix src/, t1ha1.c t1ha0.c t1ha_bits.h) Makefile

check: test
	./test

all: check32 check64

test: $(SOURCES)
	$(CC) $(CFLAGS) -DT1HA_TESTING -o $@ src/t1ha1.c src/t1ha0.c tests/main.c

clean:
	rm -f test test32 test64

test32: $(SOURCES)
	$(CC) $(CFLAGS) -DT1HA_TESTING -m32 -o $@ src/t1ha1.c src/t1ha0.c tests/main.c

check32: test32
	./test32

test64: $(SOURCES)
	$(CC) $(CFLAGS) -DT1HA_TESTING -m64 -o $@ src/t1ha1.c src/t1ha0.c tests/main.c

check64: test64
	./test64
