# T1HA_USE_FAST_ONESHOT_READ:
# Define it to 1 for little bit faster code.
# Unfortunately this may triggering a false-positive alarms from Valgrind,
# AddressSanitizer and other similar tool.
# So, define it to 0 for calmness if doubt.
T1HA_USE_FAST_ONESHOT_READ ?=1

CFLAGS ?= -std=c99 -O3 -DNDEBUG -D_DEFAULT_SOURCE
CC ?= gcc

TARGET_ARCH_e2k = $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i 'e2k' && echo yes || echo no))
TARGET_ARCH_ia32 = $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i -e '^Target: \(x86_64\)\|\([iI][3-6]86\)-.*' && echo yes || echo no))

OBJ_LIST := t1ha0.o t1ha1.o t1ha2.o
BENCH_EXTRA := bench.o mera.o test.o 4bench_xxhash.o
ifeq ($(TARGET_ARCH_e2k),yes)
TARGET_ARCH := e2k
CFLAGS += -mtune=native
OBJ_LIST += t1ha0_aes_noavx.o t1ha0_aes_avx.o
BENCH_EXTRA += 4bench_t1ha0_aes_noavx.o 4bench_t1ha0_aes_avx.o
else ifeq ($(TARGET_ARCH_ia32),yes)
TARGET_ARCH := ia32
CFLAGS += -mtune=native
OBJ_LIST += t1ha0_aes_noavx.o t1ha0_aes_avx.o t1ha0_aes_avx2.o
BENCH_EXTRA += 4bench_t1ha0_aes_noavx.o 4bench_t1ha0_aes_avx.o 4bench_t1ha0_aes_avx2.o
else
TARGET_ARCH := portable
endif

CFLAGS_TEST ?= -Wextra -Werror $(CFLAGS)
CFLAGS_LIB ?= -Wall -ffunction-sections -fPIC $(CFLAGS) -fvisibility=hidden -Dt1ha_EXPORTS

all: test libt1ha.a libt1ha.so

clean:
	rm -f test test32 test64 *.i *.bc *.s *.o *.a *.so

t1ha0.o: t1ha.h src/t1ha_bits.h src/t1ha0.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha0.c

t1ha0_aes_noavx.o_ARCH_ia32_CFLAGS = -mno-avx2 -mno-avx -maes
t1ha0_aes_noavx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h src/t1ha0_ia32aes_noavx.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -c -o $@ src/t1ha0_ia32aes_noavx.c

t1ha0_aes_avx.o_ARCH_ia32_CFLAGS = -mno-avx2 -mavx -maes
t1ha0_aes_avx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h src/t1ha0_ia32aes_avx.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -c -o $@ src/t1ha0_ia32aes_avx.c

t1ha0_aes_avx2.o_ARCH_ia32_CFLAGS = -mavx2 -mavx -maes
t1ha0_aes_avx2.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h src/t1ha0_ia32aes_avx2.c Makefile
	$(CC) $(CFLAGS_LIB) -save-temps $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -c -o $@ src/t1ha0_ia32aes_avx2.c

4bench_t1ha0_aes_noavx.o_ARCH_ia32_CFLAGS = -mno-avx2 -mno-avx -maes
4bench_t1ha0_aes_noavx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h tests/4bench_t1ha0_ia32aes_noavx.c Makefile
	$(CC) $(CFLAGS_LIB) $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -c -o $@ tests/4bench_t1ha0_ia32aes_noavx.c

4bench_t1ha0_aes_avx.o_ARCH_ia32_CFLAGS = -mno-avx2 -mavx -maes
4bench_t1ha0_aes_avx.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h tests/4bench_t1ha0_ia32aes_avx.c Makefile
	$(CC) $(CFLAGS_LIB) $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -c -o $@ tests/4bench_t1ha0_ia32aes_avx.c

4bench_t1ha0_aes_avx2.o_ARCH_ia32_CFLAGS = -mavx2 -mavx -maes
4bench_t1ha0_aes_avx2.o: t1ha.h src/t1ha_bits.h src/t1ha0_ia32aes_a.h src/t1ha0_ia32aes_b.h tests/4bench_t1ha0_ia32aes_avx2.c Makefile
	$(CC) $(CFLAGS_LIB) $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -c -o $@ tests/4bench_t1ha0_ia32aes_avx2.c

t1ha1.o: t1ha.h src/t1ha_bits.h src/t1ha1.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha1.c

t1ha2.o: t1ha.h src/t1ha_bits.h src/t1ha2.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha2.c

libt1ha.a: $(OBJ_LIST) Makefile
	$(AR) rs $@ $(OBJ_LIST)

libt1ha.so: $(OBJ_LIST) Makefile
	$(CC) $(CFLAGS) -shared -s -o $@ $(OBJ_LIST)

###############################################################################

mera.o: t1ha.h tests/mera.h tests/mera.c \
		Makefile
	$(CC) $(CFLAGS_TEST) -save-temps -c -o $@ tests/mera.c

bench.o: t1ha.h tests/common.h tests/mera.h tests/bench.c \
		Makefile
	$(CC) $(CFLAGS_TEST) -c -o $@ tests/bench.c

test.o: t1ha.h tests/common.h tests/mera.h tests/test.c \
		Makefile
	$(CC) $(CFLAGS_TEST) -c -o $@ tests/test.c

4bench_xxhash.o: tests/xxhash/xxhash.h tests/xxhash/xxhash.c \
		Makefile
	$(CC) $(CFLAGS_TEST) -Wno-error -c -o $@ tests/xxhash/xxhash.c

test: $(OBJ_LIST) $(BENCH_EXTRA) tests/main.c Makefile \
		t1ha.h tests/common.h tests/mera.h \
		mera.o bench.o test.o
	@echo "Target-ARCH: $(TARGET_ARCH)" || true
	$(CC) $(CFLAGS_TEST) -o $@ tests/main.c $(OBJ_LIST) $(BENCH_EXTRA)

check: test
	./test

bench-verbose: test
	./test --bench-verbose

###############################################################################

CROSS_LIST = sh4-linux-gnu-gcc alpha-linux-gnu-gcc \
	powerpc64-linux-gnu-gcc powerpc-linux-gnu-gcc \
	mips64-linux-gnuabi64-gcc mips-linux-gnu-gcc \
	arm-linux-gnueabihf-gcc aarch64-linux-gnu-gcc \
	sparc64-linux-gnu-gcc

# hppa-linux-gnu-gcc	- don't supported by current qemu release
# s390x-linux-gnu-gcc	- qemu troubles (hang/abort)
CROSS_LIST_NOQEMU = hppa-linux-gnu-gcc s390x-linux-gnu-gcc

cross-gcc:
	@echo "CORRESPONDING CROSS-COMPILERs ARE REQUIRED."
	@echo "FOR INSTANCE: apt install gcc-aarch64-linux-gnu gcc-alpha-linux-gnu gcc-arm-linux-gnueabihf gcc-hppa-linux-gnu gcc-mips-linux-gnu gcc-mips64-linux-gnuabi64 gcc-powerpc-linux-gnu gcc-powerpc64-linux-gnu gcc-s390x-linux-gnu gcc-sh4-linux-gnu"
	@for CC in $(CROSS_LIST_NOQEMU) $(CROSS_LIST); do \
		echo "===================== $$CC"; \
		$(MAKE) clean && CC=$$CC $(MAKE) all || exit $$?; \
	done

cross-qemu:
	@echo "CORRESPONDING CROSS-COMPILERs AND QEMUs ARE REQUIRED."
	@echo "FOR INSTANCE: apt install binfmt-support qemu-user-static qemu-user qemu-system-arm qemu-system-mips qemu-system-misc qemu-system-ppc qemu-system-sparc gcc-aarch64-linux-gnu gcc-alpha-linux-gnu gcc-arm-linux-gnueabihf gcc-hppa-linux-gnu gcc-mips-linux-gnu gcc-mips64-linux-gnuabi64 gcc-powerpc-linux-gnu gcc-powerpc64-linux-gnu gcc-s390x-linux-gnu gcc-sh4-linux-gnu"
	@for CC in $(CROSS_LIST); do \
		echo "===================== $$CC + qemu"; \
		$(MAKE) clean && CC=$$CC CFLAGS_TEST="-std=c99 -static" $(MAKE) bench-verbose || exit $$?; \
	done
