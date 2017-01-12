CC ?= cc
# LY: -march=native is a workaround for a GCC 4.x bug,
# which was fixed in 5.0 and later.
CFLAGS ?= -std=c99 -march=native -Wextra -Werror -O

check: test
	./test

all: check32 check64

test: test.c t1ha.c t1ha.h Makefile
	$(CC) $(CFLAGS) -o $@ t1ha.c test.c

clean:
	rm -f test test32 test64

test32: test.c t1ha.c t1ha.h Makefile
	$(CC) $(CFLAGS) -m32 -o $@ t1ha.c test.c

check32: test32
	./test32

test64: test.c t1ha.c t1ha.h Makefile
	$(CC) $(CFLAGS) -m64 -o $@ t1ha.c test.c

check64: test64
	./test64
