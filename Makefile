# T1HA_USE_FAST_ONESHOT_READ:
# Define it to 1 for little bit faster code.
# Unfortunately this may triggering a false-positive alarms from Valgrind,
# AddressSanitizer and other similar tool.
# So, define it to 0 for calmness if doubt.
T1HA_USE_FAST_ONESHOT_READ ?=1

CFLAGS ?= -std=c99
CC ?= gcc

TARGET_ARCHx86 = $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i -e '^Target: \(x86_64\)\|\([iI][3-6]86\)-.*' && echo yes || echo no))

OBJ_LIST := t1ha0.o t1ha1.o
ifeq ($(TARGET_ARCHx86),yes)
OBJ_LIST += t1ha0_aes_avx.o t1ha0_aes_noavx.o
endif

CFLAGS_TEST ?= -Wextra -Werror -O -g $(CFLAGS)
CFLAGS_LIB ?= -Wall -ffunction-sections -O3 -fPIC -g $(CFLAGS) -fvisibility=hidden -Dt1ha_EXPORTS

all: test libt1ha.a libt1ha.so
	./test || rm -rf libt1ha.a libt1ha.so

t1ha0.o: t1ha.h src/t1ha_bits.h src/t1ha0.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha0.c

t1ha0_aes_avx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes.h src/t1ha0_ia32aes_avx.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps -mavx -maes -c -o $@ src/t1ha0_ia32aes_avx.c

t1ha0_aes_noavx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes.h src/t1ha0_ia32aes_noavx.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps -mno-avx -maes -c -o $@ src/t1ha0_ia32aes_noavx.c

t1ha1.o: t1ha.h src/t1ha_bits.h src/t1ha1.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha1.c

libt1ha.a: $(OBJ_LIST) test Makefile
	$(AR) rs $@ $(OBJ_LIST)

libt1ha.so: $(OBJ_LIST) test Makefile
	$(CC) $(CFLAGS) -shared -s -o $@ $(OBJ_LIST)

test: $(OBJ_LIST) tests/main.c Makefile
	@echo "Target-ARCHx86: $(TARGET_ARCHx86)" || true
	$(CC) $(CFLAGS_TEST) -o $@ tests/main.c $(OBJ_LIST)

clean:
	rm -f test test32 test64 *.i *.bc *.s *.o *.a *.so

#check: check32 check64
#
#test32: $(SOURCES)
#	$(CC) $(CFLAGS_TEST) -m32 -o $@ src/t1ha1.c src/t1ha0.c tests/main.c
#
#check32: test32
#	./test32
#
#test64: $(SOURCES)
#	$(CC) $(CFLAGS_TEST) -m64 -o $@ src/t1ha1.c src/t1ha0.c tests/main.c
#
#check64: test64
#	./test64
