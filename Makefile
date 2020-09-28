# GNU Makefile for t1ha, https://abf.io/erthink/t1ha

########################################################################

# T1HA_USE_FAST_ONESHOT_READ:
# Define it to 1 for little bit faster code.
# Unfortunately this may triggering a false-positive alarms from Valgrind,
# AddressSanitizer and other similar tool.
# So, define it to 0 for calmness if doubt.
T1HA_USE_FAST_ONESHOT_READ ?=1

# To use the Intel compiler you need something like this
#CC=/opt/intel/compilers_and_libraries/linux/bin/intel64/icc
#CXX=/opt/intel/compilers_and_libraries/linux/bin/intel64/icc
#LD=/opt/intel/compilers_and_libraries/linux/bin/intel64/xild
#AR=/opt/intel/compilers_and_libraries/linux/bin/intel64/xiar
#TARGET_ARCH_ia32=yes

CC ?= gcc
CXX ?= g++

# T1HA_EXTRA_CFLAGS ?= -DT1HA_USE_INDIRECT_FUNCTIONS=0 -m32

CFLAGS ?= $(T1HA_EXTRA_CFLAGS) -std=c11 -O3 -DNDEBUG -D_DEFAULT_SOURCE -fno-stack-protector
CXXFLAGS = -std=c++11 $(filter-out -std=c11,$(CFLAGS))

TARGET_ARCH_e2k ?= $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i 'e2k' && echo yes || echo no))
TARGET_ARCH_ia32 ?= $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i -e '^Target: \(x86_64\)\|\([iI][3-6]86\)-.*' && echo yes || echo no))
TARGET_ARCH_ppc ?= $(shell (export LC_ALL=C; ($(CC) --version 2>&1; $(CC) -v 2>&1) | grep -q -i -e '^Target: powerpc.*' && echo yes || echo no))

OBJ_LIST := t1ha0.o t1ha1.o t1ha2.o t1ha0_selfcheck.o t1ha1_selfcheck.o t1ha2_selfcheck.o t1ha_selfcheck.o t1ha_selfcheck_all.o
BENCH_EXTRA := bench.o mera.o test.o 4bench_xxhash.o 4bench_stadtx.o  4bench_wyhash.o 4bench_highwayhash_test.o 4bench_highwayhash_pure_c.o 4bench_highwayhash_portable.o
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
CXXFLAGS_TEST ?= -Wextra -Werror $(CXXFLAGS)
CFLAGS_LIB ?= -Wall -ffunction-sections -fPIC $(CFLAGS) -fvisibility=hidden -Dt1ha_EXPORTS

all: test libt1ha.a libt1ha.so

clean:
	rm -f test test32 test64 *.i *.bc *.s *.o *.a *.so

CLANG_FORMAT ?= $(shell (which clang-format || which clang-format-10 || which clang-format-11 || which clang-format-12) 2>/dev/null)

reformat:
	@if [ -n "$(CLANG_FORMAT)" ]; then \
		git ls-files | grep -E '\.(c|cxx|cc|cpp|h|hxx|hpp)(\.in)?$$' | xargs -r $(CLANG_FORMAT) -i --style=file; \
	else \
		echo "clang-format version 8..12 not found for 'reformat'"; \
	fi

t1ha_selfcheck.o: t1ha.h src/t1ha_bits.h src/t1ha_selfcheck.h src/t1ha_selfcheck.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha_selfcheck.c

t1ha_selfcheck_all.o: t1ha.h src/t1ha_bits.h src/t1ha_selfcheck.h src/t1ha_selfcheck_all.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha_selfcheck_all.c

t1ha0.o: t1ha.h src/t1ha_bits.h src/t1ha0.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha0.c

t1ha0_selfcheck.o: t1ha.h src/t1ha_bits.h src/t1ha0_selfcheck.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha0_selfcheck.c

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

t1ha1_selfcheck.o: t1ha.h src/t1ha_bits.h src/t1ha1_selfcheck.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha1_selfcheck.c

t1ha2.o: t1ha.h src/t1ha_bits.h src/t1ha2.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha2.c

t1ha2_selfcheck.o: t1ha.h src/t1ha_bits.h src/t1ha2_selfcheck.c Makefile
	$(CC) $(CFLAGS_LIB) -c -o $@ src/t1ha2_selfcheck.c

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
		tests/xxhash/xxh_thunk.c tests/common.h Makefile
	$(CC) $(CFLAGS_TEST) -Wno-error -c -o $@ tests/xxhash/xxh_thunk.c

4bench_stadtx.o: tests/common.h tests/stadtx/stadtx_hash.h \
		tests/stadtx/stadtx_thunk.c tests/common.h Makefile
	$(CC) $(CFLAGS_TEST) -Wno-error -c -o $@ tests/stadtx/stadtx_thunk.c

4bench_wyhash.o: tests/wyhash/wyhash.h tests/wyhash/wyhash_thunk.c \
		tests/common.h Makefile
	$(CC) $(CFLAGS_TEST) -Wno-error -c -o $@ tests/wyhash/wyhash_thunk.c

4bench_highwayhash_pure_c.o: tests/highwayhash/pure_c.h \
		tests/highwayhash/pure_c.c Makefile
	$(CC) $(CFLAGS_TEST) -Wno-error -c -o $@ tests/highwayhash/pure_c.c

HIGHWAYHASH_SRC = $(addprefix tests/highwayhash/, \
	arch_specific.cc arch_specific.h compiler_specific.h \
	endianess.h hh_types.h hh_buffer.h highwayhash.h \
	highwayhash_target.cc highwayhash_target.h iaca.h \
	load3.h vector128.h vector256.h)

4bench_highwayhash_portable.o: $(addprefix tests/highwayhash/, \
		hh_portable.cc hh_portable.h 4bench_portable.cc) \
		$(HIGHWAYHASH_SRC) tests/common.h Makefile
	$(CXX) -I tests $(CXXFLAGS_TEST) -Wno-error -c -o $@ tests/highwayhash/4bench_portable.cc

4bench_highwayhash_avx2.o_ARCH_ia32_CFLAGS = -mavx2
4bench_highwayhash_avx2.o: $(addprefix tests/highwayhash/, \
		hh_avx2.cc hh_avx2.h 4bench_avx2.cc) \
		$(HIGHWAYHASH_SRC) tests/common.h Makefile
	$(CXX) -I tests $(CXXFLAGS_TEST) $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -Wno-error -c -o $@ tests/highwayhash/4bench_avx2.cc

4bench_highwayhash_sse41.o_ARCH_ia32_CFLAGS = -msse4.1
4bench_highwayhash_sse41.o: $(addprefix tests/highwayhash/, \
		hh_sse41.cc hh_sse41.h 4bench_sse41.cc) \
		$(HIGHWAYHASH_SRC) tests/common.h Makefile
	$(CXX) -I tests $(CXXFLAGS_TEST) $($(@)_ARCH_$(TARGET_ARCH)_CFLAGS) -Wno-error -c -o $@ tests/highwayhash/4bench_sse41.cc

ifeq ($(TARGET_ARCH_ia32),yes)
BENCH_EXTRA += 4bench_highwayhash_avx2.o 4bench_highwayhash_sse41.o
endif

4bench_highwayhash_vsx.o: $(addprefix tests/highwayhash/, \
		hh_vsx.cc hh_vsx.h 4bench_vsx.cc) \
		$(HIGHWAYHASH_SRC) tests/common.h Makefile
	$(CXX) -I tests $(CXXFLAGS_TEST) -mpower8-vector -mvsx -Wno-error -c -o $@ tests/highwayhash/4bench_vsx.cc

ifeq ($(TARGET_ARCH_ppc),yes)
BENCH_EXTRA += 4bench_highwayhash_vsx.o
endif

ifeq ($(TARGET_ARCH_e2k),yes)
BENCH_EXTRA += 4bench_highwayhash_sse41.o
endif

4bench_highwayhash_test.o: tests/common.h tests/highwayhash/pure_c.h \
		 tests/highwayhash/verifier.c Makefile
	$(CC) $(CFLAGS_TEST) -Wno-error -c -o $@ tests/highwayhash/verifier.c

test: $(OBJ_LIST) $(BENCH_EXTRA) tests/main.c Makefile \
		t1ha.h tests/common.h tests/mera.h \
		mera.o bench.o test.o
	@echo "Target-ARCH: $(TARGET_ARCH)" || true
	$(CC) $(CFLAGS_TEST) -o $@ tests/main.c $(OBJ_LIST) $(BENCH_EXTRA) -lm

check: test
	./test

bench: test
	./test --all-funcs --all-sizes

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
	@echo "FOR INSTANCE: apt install g++-aarch64-linux-gnu g++-alpha-linux-gnu g++-arm-linux-gnueabihf g++-hppa-linux-gnu g++-mips-linux-gnu g++-mips64-linux-gnuabi64 g++-powerpc-linux-gnu g++-powerpc64-linux-gnu g++-s390x-linux-gnu g++-sh4-linux-gnu g++-sparc64-linux-gnu"
	@for CC in $(CROSS_LIST_NOQEMU) $(CROSS_LIST); do \
		echo "===================== $$CC"; \
		$(MAKE) clean && CC=$$CC CXX=$$(echo "$$CC" | sed 's/gcc/g++/') $(MAKE) all || exit $$?; \
	done

cross-qemu:
	@echo "CORRESPONDING CROSS-COMPILERs AND QEMUs ARE REQUIRED."
	@echo "FOR INSTANCE: "
	@echo "	1) apt install g++-aarch64-linux-gnu g++-alpha-linux-gnu g++-arm-linux-gnueabihf g++-hppa-linux-gnu g++-mips-linux-gnu g++-mips64-linux-gnuabi64 g++-powerpc-linux-gnu g++-powerpc64-linux-gnu g++-s390x-linux-gnu g++-sh4-linux-gnu g++-sparc64-linux-gnu"
	@echo "	2) apt install binfmt-support qemu-user-static qemu-user qemu-system-arm qemu-system-mips qemu-system-misc qemu-system-ppc qemu-system-sparc"
	@for CC in $(CROSS_LIST); do \
		echo "===================== $$CC + qemu"; \
		$(MAKE) clean && CC=$$CC CXX=$$(echo "$$CC" | sed 's/gcc/g++/') CFLAGS_TEST="-std=c11 -static" $(MAKE) bench-verbose || exit $$?; \
	done
