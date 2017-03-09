CC ?= cc
# LY: -march=native is a workaround for a GCC 4.x bug,
# which was fixed in 5.0 and later.
CFLAGS ?= -std=c99 -march=native

CFLAGS_TEST ?= $(CFLAGS) -Wextra -Werror -O -g -DT1HA_TESTING
CFLAGS_LIB ?= $(CFLAGS) -Wall -ffunction-sections -O3 -fPIC
CFLAGS_SOLIB ?= $(CFLAGS_LIB) -fvisibility=hidden -Dt1ha_EXPORTS -shared

SOURCES = t1ha.h tests/main.c $(addprefix src/, t1ha1.c t1ha0.c t1ha_bits.h) Makefile

all: test libt1ha.a libt1ha.so
	./test || rm -rf libt1ha.a libt1ha.so

check: check32 check64

t1ha0.o: $(SOURCES)
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha0.c

t1ha1.o: $(SOURCES)
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha1.c

libt1ha.a: t1ha0.o t1ha1.o test
	$(AR) rs $@ t1ha0.o t1ha1.o

libt1ha.so: $(SOURCES) test
	$(CC) $(CFLAGS_SOLIB) -o $@ src/t1ha1.c src/t1ha0.c

test: $(SOURCES)
	$(CC) $(CFLAGS_TEST) -o $@ src/t1ha1.c src/t1ha0.c tests/main.c

clean:
	rm -f test test32 test64 *.o *.a *.so

test32: $(SOURCES)
	$(CC) $(CFLAGS_TEST) -m32 -o $@ src/t1ha1.c src/t1ha0.c tests/main.c

check32: test32
	./test32

test64: $(SOURCES)
	$(CC) $(CFLAGS_TEST) -m64 -o $@ src/t1ha1.c src/t1ha0.c tests/main.c

check64: test64
	./test64
