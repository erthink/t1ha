ifndef CFLAGS
CFLAGS = -std=c99
GCC_VERSION = $(shell $(CC) -v 2>&1 | sed -n 's/.*gcc version \([0-9]\+\.[0-9]\+\)\.[0-9]\+.*/\1/p')
GCC_SIMD = $(shell $(CC) -v 2>&1 | sed -n 's/^Target: \(\(x86_64\)\|\(i[3-6]86\)\)-.*/yes/p')
CLANG_VERSION = $(shell $(CC) --version 2>&1 | sed -n 's/.*clang version \([0-9]\+\.[0-9]\+\)\.[0-9]\+.*/\1/p')
CLANG_SIMD = $(shell $(CC) --version 2>&1 | sed -n 's/^Target: \(\(x86_64\)\|\(i[3-6]86\)\)-.*/yes/p')
parenthesis=)
GCC_SIMD_BUG = $(shell if [ \"$(GCC_SIMD)\" = \"yes\" ]; then case \"$(GCC_VERSION)\" in \"4.[0-8]\"$(parenthesis) echo yes;; esac; fi)
CLANG_SIMD_BUG = $(shell if [ \"$(CLANG_SIMD)\" = \"yes\" ]; then case \"$(CLANG_VERSION)\" in \"3.[0-7]\"$(parenthesis) echo yes;; esac; fi)
ifeq ($(GCC_SIMD_BUG),yes)
# LY: -march=native is a workaround for a GCC 4.x bug, which was fixed in 4.9 and later.
CFLAGS += -march=native
else
ifeq ($(CLANG_SIMD_BUG),yes)
# LY: -march=native is a workaround for a clang 3.x bug, which was fixed in 3.8 and later.
CFLAGS += -march=native
endif
endif
endif

CFLAGS_TEST ?= -Wextra -Werror -O -g -DT1HA_TESTING $(CFLAGS)
CFLAGS_LIB ?= -Wall -ffunction-sections -O3 -fPIC -g $(CFLAGS)
CFLAGS_SOLIB ?= $(CFLAGS_LIB) -fvisibility=hidden -Dt1ha_EXPORTS -shared -s

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
	@echo "GCC_VERSION=$(GCC_VERSION) GCC_SIMD=$(GCC_SIMD) CLANG_VERSION=$(CLANG_VERSION) CLANG_SIMD=$(CLANG_SIMD)"
	@echo "GCC_SIMD_BUG=$(GCC_SIMD_BUG) CLANG_SIMD_BUG=$(CLANG_SIMD_BUG)"
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
