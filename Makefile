# T1HA_USE_FAST_ONESHOT_READ:
# Define it to 1 for little bit faster code.
# Unfortunately this may triggering a false-positive alarms from Valgrind,
# AddressSanitizer and other similar tool.
# So, define it to 0 for calmness if doubt.
T1HA_USE_FAST_ONESHOT_READ ?=1

TARGET_ARCHe2k = $(shell (uname -m | grep -q -i -e e2k && echo yes || echo no))

ifeq ($(TARGET_ARCHe2k),yes)
TARGET_ARCHx86 = no
CC = /home/admlcc/ecomp.rel-i-1/lcc_e
#CFLAGS = -std=c99 -mcpu=elbrus-v3 -O0 -g -ffast
#CFLAGS = -std=c99 -mcpu=elbrus-v3 -O4 -fno-comb-oper
CFLAGS = -std=c99 -mcpu=elbrus-v3 -O4 -g -ffast -fno-comb-oper
CFLAGS_LIB ?= -Wall -ffunction-sections -fPIC $(CFLAGS) -fvisibility=hidden -Dt1ha_EXPORTS
MAVX2 =
MNO_AVX2 =
MNO_AVX =
else
CC ?= gcc
CFLAGS ?= -std=c99
CFLAGS_LIB ?= -Wall -ffunction-sections -O3 -fPIC -g $(CFLAGS) -fvisibility=hidden -Dt1ha_EXPORTS

TARGET_ARCHx86 = $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i -e '^Target: \(x86_64\)\|\([iI][3-6]86\)-.*' && echo yes || echo no))
endif

OBJ_LIST := t1ha0.o t1ha1.o t1ha2.o
BENCH_EXTRA :=
ifneq ($(findstring yes, $(TARGET_ARCHx86)$(TARGET_ARCHe2k)),)
OBJ_LIST += t1ha0_aes_noavx.o t1ha0_aes_avx.o t1ha0_aes_avx2.o
BENCH_EXTRA += 4bench_t1ha0_aes_noavx.o 4bench_t1ha0_aes_avx.o 4bench_t1ha0_aes_avx2.o
endif

CFLAGS_TEST ?= -Wextra -Werror -O -g $(CFLAGS)

all: test libt1ha.a libt1ha.so

ifeq ($(TARGET_ARCHx86),yes)
MAVX2 = -mavx2
MNO_AVX2 = -mno-avx2
MNO_AVX = -mno-avx
endif

t1ha0.o: t1ha.h src/t1ha_bits.h src/t1ha0.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha0.c

t1ha0_aes_noavx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h src/t1ha0_ia32aes_noavx.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps $(MNO_AVX2) $(MNO_AVX) -maes -c -o $@ src/t1ha0_ia32aes_noavx.c

t1ha0_aes_avx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h src/t1ha0_ia32aes_avx.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps $(MNO_AVX2) -mavx -maes -c -o $@ src/t1ha0_ia32aes_avx.c

t1ha0_aes_avx2.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h src/t1ha0_ia32aes_avx2.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps $(MAVX2) -mavx -maes -c -o $@ src/t1ha0_ia32aes_avx2.c

4bench_t1ha0_aes_noavx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h tests/4bench_t1ha0_ia32aes_noavx.c Makefile
	$(CC) $(CFLAGS_LIB) $(MNO_AVX2) $(MNO_AVX) -maes -c -o $@ tests/4bench_t1ha0_ia32aes_noavx.c

4bench_t1ha0_aes_avx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h tests/4bench_t1ha0_ia32aes_avx.c Makefile
	$(CC) $(CFLAGS_LIB) $(MNO_AVX2) -mavx -maes -c -o $@ tests/4bench_t1ha0_ia32aes_avx.c

4bench_t1ha0_aes_avx2.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h tests/4bench_t1ha0_ia32aes_avx2.c Makefile
	$(CC) $(CFLAGS_LIB) $(MAVX2) -mavx -maes -c -o $@ tests/4bench_t1ha0_ia32aes_avx2.c

t1ha1.o: t1ha.h src/t1ha_bits.h src/t1ha1.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha1.c

t1ha2.o: t1ha.h src/t1ha_bits.h src/t1ha2.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha2.c

libt1ha.a: $(OBJ_LIST) test Makefile
	$(AR) rs $@ $(OBJ_LIST)

libt1ha.so: $(OBJ_LIST) test Makefile
	$(CC) $(CFLAGS) -shared -s -o $@ $(OBJ_LIST)

test: $(OBJ_LIST) $(BENCH_EXTRA) tests/main.c Makefile
	@echo "Target-ARCHx86: $(TARGET_ARCHx86)" || true
	@echo "Target-ARCHe2k: $(TARGET_ARCHe2k)" || true
	$(CC) $(CFLAGS_TEST) -o $@ tests/main.c $(OBJ_LIST) $(BENCH_EXTRA)

check: test
	./test || rm -rf libt1ha.a libt1ha.so

clean:
	rm -f test test32 test64 *.i *.bc *.s *.o *.a *.so
