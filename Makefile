CC ?= cc

check: test
	./test

all: check32 check64

test: test.c t1ha.c t1ha.h Makefile
	$(CC) -std=c99 -march=native -Wall -O -o $@ t1ha.c test.c

clean:
	rm -f test test32 test64

test32: test.c t1ha.c t1ha.h Makefile
	$(CC) -m32 -std=c99 -march=native -Wall -O -o $@ t1ha.c test.c

check32: test32
	./test32

test64: test.c t1ha.c t1ha.h Makefile
	$(CC) -m64 -std=c99 -march=native -Wall -O -o $@ t1ha.c test.c

check64: test64
	./test64
