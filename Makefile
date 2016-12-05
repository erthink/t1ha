all: check

test: test.c t1ha.c t1ha.h Makefile
	cc -std=c99 -march=native -Wall -O -o $@ t1ha.c test.c

check: test
	./test
