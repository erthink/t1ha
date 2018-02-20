/*
 *  Copyright (c) 2016-2018 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2018 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _ISOC99_SOURCE
#define _ISOC99_SOURCE 1
#endif

#ifndef _ISOC11_SOURCE
#define _ISOC11_SOURCE 1
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS 1
#endif

#ifndef _THREAD_SAFE
#define _THREAD_SAFE 1
#endif

#ifndef _REENTRANT
#define _REENTRANT 1
#endif

#if defined(_MSC_VER)
#pragma warning(disable : 4711) /* function 'xyz' selected for                 \
                                   automatic inline expansion */
#pragma warning(disable : 4127) /* conditional expression is constant */
#pragma warning(disable : 4702) /* unreachable code */
#if _MSC_VER < 1900
#define snprintf _snprintf
#pragma warning(disable : 4996) /* '_snprintf': This function or variable      \
                                   may be unsafe */
#endif
#if _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif
#endif /* MSVC */

/* OS's includes for time/clock */
#if defined(__linux__) || defined(__gnu_linux__)
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif /* Linux */

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#elif defined(__APPLE__) || defined(__MACH__)
#include <mach/mach_time.h>
#include <mach/thread_policy.h>
#endif

#if defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
#include <time.h>
#include <windows.h>
#include <winnt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#endif /* OS */

#include "bench.h"

/*****************************************************************************/

/* Compiler's includes for builtins/intrinsics */
#ifdef _MSC_VER
#include <intrin.h>
#elif __GNUC_PREREQ(4, 4) || defined(__clang__)
#if T1HA_IA32_AVAILABLE || defined(__e2k__)
#include <cpuid.h>
#include <x86intrin.h>
#endif /* T1HA_IA32_AVAILABLE */
#elif defined(__INTEL_COMPILER)
#include <intrin.h>
#elif defined(__SUNPRO_C) || defined(__sun) || defined(sun)
#include <mbarrier.h>
#elif (defined(_HPUX_SOURCE) || defined(__hpux) || defined(__HP_aCC)) &&       \
    (defined(HP_IA64) || defined(__ia64))
#include <machine/sys/inline.h>
#elif defined(__IBMC__) && defined(__powerpc)
#include <atomic.h>
#elif defined(_AIX)
#include <builtins.h>
#include <sys/atomic_op.h>
#elif (defined(__osf__) && defined(__DECC)) || defined(__alpha)
#include <c_asm.h>
#include <machine/builtins.h>
#elif defined(__MWERKS__)
/* CodeWarrior - troubles ? */
#pragma gcc_extensions
#elif defined(__SNC__)
/* Sony PS3 - troubles ? */
#elif defined(__hppa__) || defined(__hppa)
#include <machine/inline.h>
#else
#error Unsupported C compiler, please use GNU C 4.4 or newer
#endif /* Compiler */

static __inline void compiler_barrier(void) {
#if defined(__clang__) || defined(__GNUC__)
  __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
  _ReadWriteBarrier();
#elif defined(__INTEL_COMPILER) /* LY: Intel Compiler may mimic GCC and MSC */
  __memory_barrier();
  if (type > MDBX_BARRIER_COMPILER)
#if defined(__ia64__) || defined(__ia64) || defined(_M_IA64)
    __mf();
#elif defined(__i386__) || defined(__x86_64__)
    _mm_mfence();
#else
#error "Unknown target for Intel Compiler, please report to us."
#endif
#elif defined(__SUNPRO_C) || defined(__sun) || defined(sun)
  __compiler_barrier();
#elif (defined(_HPUX_SOURCE) || defined(__hpux) || defined(__HP_aCC)) &&       \
    (defined(HP_IA64) || defined(__ia64))
  _Asm_sched_fence(/* LY: no-arg meaning 'all expect ALU', e.g. 0x3D3D */);
#elif defined(_AIX) || defined(__ppc__) || defined(__powerpc__) ||             \
    defined(__ppc64__) || defined(__powerpc64__)
  __fence();
#else
#error "Could not guess the kind of compiler, please report to us."
#endif
}

/*****************************************************************************/

#if defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
static unsigned seh_filter(unsigned exception_code) {
  switch (exception_code) {
  case EXCEPTION_ILLEGAL_INSTRUCTION:
  case EXCEPTION_PRIV_INSTRUCTION:
  case EXCEPTION_ACCESS_VIOLATION:
    return EXCEPTION_EXECUTE_HANDLER;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
#else
static sigjmp_buf sigaction_jump;
static void sigaction_handler(int signum, siginfo_t *info, void *context) {
  (void)context;
  (void)info;
  siglongjmp(sigaction_jump, signum);
}
#endif

static int probe(unsigned (*start)(timestamp_t *),
                 unsigned (*fihish)(timestamp_t *)) {
#if defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
  __try {
#else
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_sigaction = sigaction_handler;
  if (sigaction(SIGSEGV, &act, NULL) || sigaction(SIGILL, &act, NULL) ||
      sigaction(SIGBUS, &act, NULL)) {
    perror("sigaction(SIGSEGV)");
    return 1;
  }

  if (sigsetjmp(sigaction_jump, 0) != 0)
    return -1;
#endif

    int rc = -1;
    for (unsigned n = 0; n < 42; ++n) {
      timestamp_t timestamp_start, timestamp_fihish;
      unsigned coreid = start(&timestamp_start);
#if defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
      Sleep(1);
#else
    usleep(42);
#endif
      if (coreid != fihish(&timestamp_fihish))
        rc = -2;
      else if (timestamp_fihish <= timestamp_start)
        rc = -3;
      else
        return 0;
    }
    return rc;

#if defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
  } __except (seh_filter(GetExceptionCode())) {
    return -1;
  }
#endif
}

/*****************************************************************************/

static int set_single_affinity(void) {
#if defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||              \
    defined(__WINDOWS__)
  return -1;
#elif defined(__GLIBC__) || defined(__GNU_LIBRARY__) || defined(__ANDROID__)
  const unsigned ncpu = sysconf(_SC_NPROCESSORS_CONF);
  const unsigned cpuset_size = CPU_ALLOC_SIZE(ncpu);
  cpu_set_t *affinity = CPU_ALLOC(ncpu);
  if (!affinity) {
    perror("CPU_ALLOC()");
    return -1;
  }
  const int current_cpu = sched_getcpu();
  if (current_cpu < 0) {
    perror("sched_getcpu()");
    CPU_FREE(affinity);
    return -1;
  }
  CPU_ZERO_S(cpuset_size, affinity);
  CPU_SET_S(current_cpu, cpuset_size, affinity);
  if (sched_setaffinity(0, sizeof(affinity), affinity)) {
    perror("sched_setaffinity()");
    CPU_FREE(affinity);
    return -1;
  }
  CPU_FREE(affinity);
  return 0;
#elif defined(__APPLE__) || defined(__MACH__)
  return -1;
#else
  return -1;
#endif
}

/*****************************************************************************/

union timestamp {
  uint64_t u64;
  struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32_t h, l;
#else
    uint32_t l, h;
#endif
  } u32;
};

static unsigned clock_fallback(timestamp_t *now) {
  compiler_barrier();
  unsigned coreid = 0;

#if defined(__APPLE__) || defined(__MACH__)
#define UNITS "ns"
#define SOURCE "mach_absolute_time()"
#define FLAGS 0
#define RATIO runtime

  *now = mach_absolute_time();

#elif defined(EMSCRIPTEN)
#define UNITS "ns"
#define SOURCE "emscripten_get_now()"
#define FLAGS 0
#define RATIO 1e6
  *now = (timestamp_t)(emscripten_get_now() * 1e6);

#elif defined(__e2k__)
#define UNITS "clk"
#define SOURCE "RDTSCP"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  *now = __rdtscp(&coreid);

#elif (defined(__powerpc64__) || defined(__ppc64__) || defined(__ppc64) ||     \
       defined(__powerpc64)) &&                                                \
    defined(__GNUC__)
#define UNITS "clk"
#define SOURCE "MFSPR(268)"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  uint64_t ticks;
  __asm __volatile("mfspr %0, 268" : "=r"(ticks));
  *now = ticks;

#elif (defined(__powerpc__) || defined(__ppc__)) && defined(__GNUC__)
/* A time-base timer, which is not always precisely a cycle-count. */
#if UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul
#define UNITS "tick"
#define SOURCE "MFTB"
#define FLAGS timestamp_clock_cheap
#define RATIO 1
  uint64_t ticks;
  __asm __volatile("mftb  %0" : "=r"(ticks));
  *now = ticks;
#else
#define UNITS "tick"
#define SOURCE "MFTB+MFTBU"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  unsigned long low, high_before, high_after;
  __asm __volatile("mftbu %0; mftb  %1; mftbu %2"
                   : "=r"(high_before), "=r"(low), "=r"(high_after));
  union timestamp *u = (union timestamp *)now;
  u->u32.h = high_after;
  u->u32.l = low & /* zeroes if high part has changed */
             ~(high_before - high_after);
#endif

#elif defined(__sparc_v9__) && defined(__GNUC__)
#define UNITS "clk"
#define SOURCE "tick register"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  uint64_t cycles;
  __asm __volatile("rd %%tick, %0" : "=r"(cycles));
  *now = cycles;

#elif (defined(__sparc__) || defined(__sparc)) && defined(__GNUC__)
#define UNITS "clk"
#define SOURCE "tick register"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  uint64_t ticks;
  __asm __volatile(".byte 0x83, 0x41, 0x00, 0x00; mov %%g1, %0"
                   : "=r"(ticks)::"%g1");
  *now = ticks;

#elif (defined(__ia64__) || defined(__ia64)) && defined(__GNUC__)
#define UNITS "clk"
#define SOURCE "ITC"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  uint64_t ticks;
  __asm __volatile("mov %0 = ar.itc" : "=r"(ticks));
  *now = ticks;
#elif (defined(__EDG_VERSION) || defined(__ECC)) && defined(__ia64__)
#define UNITS "clk"
#define SOURCE "ITC"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  *now = __getReg(_IA64_REG_AR_ITC);
#elif defined(__hpux) && defined(__ia64)
#define RATIO 1
#define SOURCE "ITC"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define UNITS "clk"
  *now = _Asm_mov_from_ar(_AREG_ITC);

#elif (defined(__hppa__) || defined(__hppa)) && defined(__GNUC__)
#define UNITS "clk"
#define SOURCE "MFCTL(16)"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  uint64_t ticks;
#ifdef __GNUC__
  __asm __volatile("mfctl 16, %0" : "=r"(ticks));
#else
  _MFCTL(16, ticks);
#endif
  *now = ticks;

#elif defined(__aarch64__)
/* System timer of ARMv8 runs at a different frequency than the CPU's.
 * The frequency is fixed, typically in the range 1-50MHz.  It can be
 * read at CNTFRQ special register.  We assume the OS has set up
 * the virtual timer properly. */
#define UNITS "tick"
#define SOURCE "VirtualTimer"
#define FLAGS timestamp_clock_cheap
#define RATIO 1
  uint64_t virtual_timer;
  __asm __volatile("mrs %0, cntvct_el0" : "=r"(virtual_timer));
  *now = virtual_timer;

#elif defined(__s390__)
#define UNITS "clk"
#define SOURCE "STCKE"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  uint8_t clk[16];
  __asm __volatile("stcke %0" : "=Q"(&clk) : : "cc");
  *now = *((unsigned long long *)&clk[1]) >> 2;

#elif defined(__alpha__)
#define UNITS "clk"
#define SOURCE "RPCC"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO 1
  unsigned long cycles;
  __asm__ __volatile("rpcc %0" : "=r"(cycles));
  *now = cycles & 0xFFFFffff;

#elif defined(TIMEBASE_SZ) || defined(__OS400__)
#define UNITS "ns"
#define SOURCE "read_wall_time(TIMEBASE_SZ)"
#define FLAGS (timestamp_clock_stable | timestamp_clock_cheap)
#define RATIO runtime
  timebasestruct_t tb;
  if (read_wall_time(&tb, TIMEBASE_SZ) != 0) {
    perror("read_wall_time(TIMEBASE_SZ)");
    abort();
  }
  union timestamp *u = (union timestamp *)now;
  u->u32.h = tb.tb_high;
  u->u32.l = tb.tb_low;

#elif defined(__sun__) || defined(__sun)
#define UNITS "ns"
#define SOURCE "gethrtime()"
#define FLAGS 0
#define RATIO 1
  *now = gethrtime();

#elif defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||            \
    defined(__WINDOWS__)
#define UNITS "ns"
#define SOURCE "QueryPerformanceCounter()"
#define FLAGS 0
#define RATIO runtime
  if (!QueryPerformanceCounter((LARGE_INTEGER *)now)) {
    perror("QueryPerformanceCounter()");
    abort();
  }

#elif defined(CLOCK_SGI_CYCLE)
#define UNITS "ns"
#define SOURCE "clock_gettime(CLOCK_SGI_CYCLE)"
#define FLAGS 0
#define RATIO 1
  struct timespec ts;
  if (clock_gettime(CLOCK_SGI_CYCLE, &ts) == 0) {
    *now = ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
  } else {
    perror("clock_gettime(CLOCK_SGI_CYCLE)");
    abort();
  }

#elif defined(CLOCK_MONOTONIC_RAW)
#define UNITS "ns"
#define SOURCE "clock_gettime(CLOCK_MONOTONIC_RAW)"
#define FLAGS 0
#define RATIO 1
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
    *now = ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
  } else {
    perror("clock_gettime(CLOCK_MONOTONIC_RAW)");
    abort();
  }

#elif defined(CLOCK_MONOTONIC)
#define UNITS "ns"
#define SOURCE "clock_gettime(CLOCK_MONOTONIC)"
#define FLAGS 0
#define RATIO 1
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    *now = ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
  } else {
    perror("clock_gettime(CLOCK_MONOTONIC)");
    abort();
  }

#else
#define UNITS "ns"
#define SOURCE "gettimeofday()"
#define FLAGS 0
#define RATIO 1e3
  struct timeval tv;
  gettimeofday(&tv, NULL);
  *now = tv.tv_sec * UINT64_C(1000000) + tv.tv_usec;
#endif
  return coreid;
}

/*****************************************************************************/

static double convert_fallback(timestamp_t timestamp) {
#if defined(__APPLE__) || defined(__MACH__)
  static double runtime /* from mach_absolute_time() to seconds */;
  if (!runtime) {
    mach_timebase_info_data_t ti;
    if (mach_timebase_info(&ti) != 0) {
      perror("mach_timebase_info()");
      abort();
    }
    runtime = (double)ti.numer / ti.denom;
  }
#elif defined(EMSCRIPTEN)
#elif defined(__e2k__)
#elif (defined(__powerpc__) || defined(__ppc__)) && defined(__GNUC__)
#elif defined(__sparc_v9__) && defined(__GNUC__)
#elif (defined(__sparc__) || defined(__sparc)) && defined(__GNUC__)
#elif (defined(__ia64__) || defined(__ia64)) && defined(__GNUC__)
#elif (defined(__EDG_VERSION) || defined(__ECC)) && defined(__ia64__)
#elif defined(__hpux) && defined(__ia64)
#elif (defined(__hppa__) || defined(__hppa)) && defined(__GNUC__)
#elif defined(__aarch64__)
#elif defined(__s390__)
#elif defined(__alpha__)
#elif defined(TIMEBASE_SZ) || defined(__OS400__)
  static double runtime /* from read_wall_time() to seconds */;
  if (!runtime) {
    timebasestruct_t tb;
    tb.tb_high = 0x7fff;
    tb.tb_low = 0;
    if (time_base_to_time(&tb, TIMEBASE_SZ) != 0) {
      perror("time_base_to_time()");
      abort();
    }
    runtime = (tb.tb_high * 1e9 + tb.tb_low) / UINT64_C(0x7fff00000000);
  }
#elif defined(__sun__) || defined(__sun)
#elif defined(_WIN64) || defined(_WIN32) || defined(__TOS_WIN__) ||            \
    defined(__WINDOWS__)
  static double runtime /* from QueryPerformanceCounter() to seconds */;
  if (!runtime) {
    LARGE_INTEGER frequency;
    if (!QueryPerformanceFrequency(&frequency)) {
      perror("QueryPerformanceFrequency()");
      abort();
    }
    runtime = 1e9 / frequency.QuadPart;
  }
#elif defined(CLOCK_SGI_CYCLE)
#elif defined(CLOCK_MONOTONIC_RAW)
#elif defined(CLOCK_MONOTONIC)
#else /* gettimeofday() */
#endif
  return timestamp * RATIO;
}

/*****************************************************************************/

static double convert_1to1(timestamp_t timestamp) { return (double)timestamp; }

#if (defined(__ARM_ARCH) && __ARM_ARCH >= 6) || defined(_M_ARM64)
static void clock_pmccntr(timestamp_t *now) {
  compiler_barrier();
#ifdef __GNUC__
  unsigned long pmccntr;
  __asm __volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
  *now = (uint64_t)pmccntr;
#else
  *now = __rdpmccntr64();
#endif
  compiler_barrier();
}

static double convert_pmccntr_x64(timestamp_t timestamp) {
  /* The counter is set up to count every 64th cycle */
  return timestamp * 64.0;
}
#endif /* __ARM_ARCH >= 6 || _M_ARM64 */

#if defined(__mips__) && defined(PROT_READ) && defined(MAP_SHARED)
static volatile uint64_t *mips_tsc_addr;

static void clock_zbustimer(timestamp_t *now) {
  compiler_barrier();
  *now = *mips_tsc_addr;
  compiler_barrier();
}

#endif /* MIPS */

#if T1HA_IA32_AVAILABLE

enum ia32_fixed_perfomance_counters {
  /* count of retired instructions on the current core in the low-order 48 bits
     of an unsigned 64-bit integer */
  ia32_COUNT_HW_INSTRUCTIONS = 1 << 30,

  /* count of actual CPU core cycles executed by the current core.  Core cycles
     are not accumulated while the processor is in the "HALT" state, which is
     used when the operating system has no task(s) to run on a processor core.
     */
  ia32_COUNT_HW_CPU_CYCLES = (1 << 30) + 1,

  /* count of "reference" (or "nominal") CPU core cycles executed by the current
     core.  This counts at the same rate as the TSC, but does not count when the
     core is in the "HALT" state.  If a timed section of code shows a larger
     change in TSC than in rdpmc_reference_cycles, the processor probably spent
     some time in a HALT state. */
  ia32_COUNT_HW_REF_CPU_CYCLES = (1 << 30) + 2,
};

static unsigned clock_rdpmc_start(timestamp_t *now) {
  compiler_barrier();
#if __GNUC__
  uint32_t low, high;
  __asm __volatile("cpuid; mov %2, %%ecx; rdpmc"
                   : "=a"(low), "=d"(high)
                   : "i"(ia32_COUNT_HW_CPU_CYCLES)
                   : "%ebx", "%ecx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
#elif defined(_MSC_VER)
  int unused[4];
  __cpuid(unused, 0);
  *now = __readpmc(ia32_COUNT_HW_CPU_CYCLES);
#else
#error "FIXME: Unsupported compiler"
#endif
  compiler_barrier();
  return 0;
}

static unsigned clock_rdpmc_finish(timestamp_t *now) {
  compiler_barrier();
#if __GNUC__
  uint32_t low, high;
  __asm __volatile("mov %2, %%ecx; rdpmc; mov %%eax, %0; mov %%edx, %1; cpuid"
                   : "=r"(low), "=r"(high)
                   : "i"(ia32_COUNT_HW_CPU_CYCLES)
                   : "%eax", "%ebx", "%ecx", "%edx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
#elif defined(_MSC_VER)
  *now = __readpmc(ia32_COUNT_HW_CPU_CYCLES);
  int unused[4];
  __cpuid(unused, 0);
#else
#error "FIXME: Unsupported compiler"
#endif
  return 0;
}

static unsigned clock_rdtscp_start(timestamp_t *now) {
  compiler_barrier();
  unsigned coreid;
  *now = __rdtscp(&coreid);
  return coreid;
}

static unsigned clock_rdtscp_fihish(timestamp_t *now) {
  compiler_barrier();
#if __GNUC__
  uint32_t low, high, coreid;
  __asm __volatile("rdtscp; mov %%eax, %0; mov %%edx, %1; mov %%ecx, %2; cpuid"
                   : "=r"(low), "=r"(high), "=r"(coreid)
                   :
                   : "%eax", "%ebx", "%ecx", "%edx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
  return coreid;
#elif defined(_MSC_VER)
  unsigned coreid;
  *now = __rdtscp(&coreid);
  int unused[4];
  __cpuid(unused, 0);
  return coreid;
#else
#error "FIXME: Unsupported compiler"
#endif
}

static unsigned clock_rdtsc_start(timestamp_t *now) {
  compiler_barrier();
#if __GNUC__
  uint32_t low, high;
  __asm __volatile("cpuid; rdtsc" : "=a"(low), "=d"(high) : : "%ebx", "%ecx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
#elif defined(_MSC_VER)
  int unused[4];
  __cpuid(unused, 0);
  *now = __rdtsc();
#else
#error "FIXME: Unsupported compiler"
#endif
  compiler_barrier();
  return 0;
}

static unsigned clock_rdtsc_finish(timestamp_t *now) {
  compiler_barrier();
#if __GNUC__
  uint32_t low, high;
  __asm __volatile("rdtsc; mov %%eax, %0; mov %%edx, %1; cpuid"
                   : "=r"(low), "=r"(high)
                   :
                   : "%eax", "%ebx", "%ecx", "%edx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
#elif defined(_MSC_VER)
  int unused[4];
  __cpuid(unused, 0);
  *now = __rdtsc();
#else
#error "FIXME: Unsupported compiler"
#endif
  compiler_barrier();
  return 0;
}

ia32_cpu_features_t ia32_cpu_features;

static void fetch_cpu_features(void) {
  memset(&ia32_cpu_features, 0, sizeof(ia32_cpu_features));
#ifdef __GNUC__
  uint32_t unused_eax, unused_ebx, cpuid_max;

  cpuid_max = __get_cpuid_max(0, NULL);
  if (cpuid_max >= 1) {
    __cpuid_count(1, 0, unused_eax, ia32_cpu_features.basic.ebx,
                  ia32_cpu_features.basic.ecx, ia32_cpu_features.basic.edx);
    if (cpuid_max >= 7)
      __cpuid_count(7, 0, unused_eax, ia32_cpu_features.extended_7.ebx,
                    ia32_cpu_features.extended_7.ecx,
                    ia32_cpu_features.extended_7.edx);
  }
  cpuid_max = __get_cpuid_max(0x80000000, NULL);
  if (cpuid_max >= 0x80000001) {
    __cpuid_count(0x80000001, 0, unused_eax, unused_ebx,
                  ia32_cpu_features.extended_80000001.ecx,
                  ia32_cpu_features.extended_80000001.edx);
    if (cpuid_max >= 0x80000007)
      __cpuid_count(0x80000007, 0, unused_eax, unused_ebx,
                    ia32_cpu_features.extended_80000007.ecx,
                    ia32_cpu_features.extended_80000007.edx);
  }

#elif defined(_MSC_VER)
  int info[4];
  __cpuid(info, 0);
  unsigned cpuid_max = info[0];
  if (cpuid_max >= 1) {
    __cpuidex(info, 1, 0);
    ia32_cpu_features.basic.ebx = info[1];
    ia32_cpu_features.basic.ecx = info[2];
    ia32_cpu_features.basic.edx = info[3];
    if (cpuid_max >= 7) {
      __cpuidex(info, 7, 0);
      ia32_cpu_features.extended_7.ebx = info[1];
      ia32_cpu_features.extended_7.ecx = info[2];
      ia32_cpu_features.extended_7.edx = info[3];
    }
  }

  __cpuid(info, 0x80000000);
  cpuid_max = info[0];
  if (cpuid_max >= 0x80000001) {
    __cpuidex(info, 0x80000001, 0);
    ia32_cpu_features.extended_80000001.ecx = info[2];
    ia32_cpu_features.extended_80000001.edx = info[3];
    if (cpuid_max >= 0x80000007) {
      __cpuidex(info, 0x80000007, 0);
      ia32_cpu_features.extended_80000007.ecx = info[2];
      ia32_cpu_features.extended_80000007.edx = info[3];
    }
  }
#else
#error "FIXME: Unsupported compiler"
#endif
}

#endif /* T1HA_IA32_AVAILABLE */

/*****************************************************************************/

#ifdef __NR_perf_event_open
static int perf_fd;
static const struct perf_event_mmap_page volatile *perf_page;
static long perf_event_open(struct perf_event_attr *event_attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, event_attr, pid, cpu, group_fd, flags);
}

static unsigned clock_perf(timestamp_t *now) {
  *now = 42;
  return read(perf_fd, now, sizeof(timestamp_t));
}

static int perf_setup(void) {
#ifdef PR_TASK_PERF_EVENTS_ENABLE
  if (prctl(PR_TASK_PERF_EVENTS_ENABLE, 1, 0, 0, 0))
    perror("prctl(PR_TASK_PERF_EVENTS_ENABLE)");
#endif /* PR_TASK_PERF_EVENTS_ENABLE */

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(struct perf_event_attr));
  attr.size = sizeof(struct perf_event_attr);
  attr.type = PERF_TYPE_HARDWARE;
  attr.config = PERF_COUNT_HW_CPU_CYCLES;
  attr.read_format = PERF_FORMAT_TOTAL_TIME_RUNNING;
  attr.disabled = 1;
  // attr.pinned = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
#ifndef PERF_FLAG_FD_CLOEXEC /* Since 3.14 */
#define PERF_FLAG_FD_CLOEXEC 0
#endif
  perf_fd = perf_event_open(&attr, 0 /* current process */, -1 /* any cpu */,
                            -1 /* no group */, PERF_FLAG_FD_CLOEXEC);
  if (perf_fd < 0) {
    perror("perf_event_open()");
    return -1;
  }

  perf_page = (struct perf_event_mmap_page *)mmap(
      NULL, getpagesize(), PROT_WRITE | PROT_READ, MAP_SHARED, perf_fd, 0);
  if (perf_page == MAP_FAILED) {
    perror("mmap(perf_event_mmap_page)");
    close(perf_fd);
    return -2;
  }

  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) /* Start counters */) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    close(perf_fd);
    perf_fd = -1;
    return -3;
  }
  return 0;
}

#if T1HA_IA32_AVAILABLE
static unsigned perf_rdpmc_index;
unsigned perf_rdpmc_start(timestamp_t *now) {
  compiler_barrier();
  uint32_t low, high;
  __asm __volatile("cpuid; mov %2, %%ecx; rdpmc"
                   : "=a"(low), "=d"(high)
                   : "m"(perf_rdpmc_index)
                   : "%ebx", "%ecx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
  return 0;
}

unsigned perf_rdpmc_finish(timestamp_t *now) {
  compiler_barrier();
  uint32_t low, high;
  __asm __volatile("mov %2, %%ecx; rdpmc; mov %%eax, %0; mov %%edx, %1; cpuid"
                   : "=r"(low), "=r"(high)
                   : "m"(perf_rdpmc_index)
                   : "%eax", "%ebx", "%ecx", "%edx");
  union timestamp *u = (union timestamp *)now;
  u->u32.l = low;
  u->u32.h = high;
  return 0;
}
#endif /* T1HA_IA32_AVAILABLE */

#endif /* __NR_perf_event_open */

/*****************************************************************************/

void mera_init(void) {
  set_single_affinity();

#ifdef PR_SET_TSC
  int tsc_mode = PR_TSC_SIGSEGV;
  if (prctl(PR_GET_TSC, &tsc_mode, 0, 0, 0)) {
    if (errno != ENOSYS)
      perror("prctl(PR_GET_TSC)");
  } else if (tsc_mode != PR_TSC_ENABLE &&
             prctl(PR_SET_TSC, PR_TSC_ENABLE, 0, 0, 0))
    perror("prctl(PR_SET_TSC, PR_TSC_ENABLE)");
#endif /* PR_SET_TSC */

#if (defined(__ARM_ARCH) && __ARM_ARCH >= 6) || defined(_M_ARM64)
  uint32_t pmuseren;
/* Read the user mode perf monitor counter access permissions. */
#ifdef __GNUC__
  __asm("mrc p15, 0, %0, c9, c14, 0" : "=r"(pmuseren));
#else
  pmuseren = _MoveFromCoprocessor(15, 0, 9, 14, 0);
#endif
  if (1 & pmuseren /* Is it allowed for user mode code? */) {
    uint32_t pmcntenset;
#ifdef __GNUC__
    __asm("mrc p15, 0, %0, c9, c12, 1" : "=r"(pmcntenset));
#else
    pmcntenset = _MoveFromCoprocessor(15, 0, 9, 12, 1);
#endif
    if ((pmcntenset & 0x80000000ul /* Is it counting? */) &&
        probe(clock_pmccntr, clock_pmccntr) == 0) {
      mera.start = mera.finish = clock_pmccntr;
      mera.convert = convert_pmccntr_x64;
      mera.units = "clk";
      mera.source = "PMCCNTR";
      mera.flags = timestamp_clock_stable | timestamp_clock_cheap;
      return;
    }
  }
#endif /* __ARM_ARCH >= 6 || _M_ARM64 */

#if defined(__mips__) && defined(PROT_READ) && defined(MAP_SHARED)
  uint64_t *mips_tsc_addr;
  int mem_fd = open("/dev/mem", O_RDONLY | O_SYNC, 0);

  if (mem_fd < 0)
    perror("open(/dev/mem)");
  else {
    mips_tsc_addr = mmap(nullptr, getpagesize(), PROT_READ, MAP_SHARED, mem_fd,
                         0x10030000 /* MIPS_ZBUS_TIMER */);
    if (mips_tsc_addr == MAP_FAILED) {
      perror("mmap(MIPS_ZBUS_TIMER)");
      close(mem_fd);
    } else {
      close(mem_fd);
      if (probe(clock_zbustimer, clock_zbustimer) == 0) {
        mera.start = mera.finish = clock_zbustimer;
        mera.convert = convert_1to1;
        mera.units = "clk";
        mera.source = "ZBUS-Timer(0x10030000)";
        mera.flags = timestamp_clock_stable | timestamp_clock_cheap;
        return;
      }
    }
  }
#endif /* MIPS */

#if __NR_perf_event_open
  bool perf_available = false;
  if (perf_setup() == 0) {
#if T1HA_IA32_AVAILABLE
    if (perf_page->cap_bit0_is_deprecated && perf_page->cap_user_rdpmc &&
        perf_page->index) {
      perf_rdpmc_index = perf_page->index - 1;
      if (probe(perf_rdpmc_start, perf_rdpmc_finish) == 0) {
        mera.convert = convert_1to1;
        mera.units = "clk";
        mera.flags = timestamp_clock_stable | timestamp_clock_cheap;
        mera.start = perf_rdpmc_start;
        mera.finish = perf_rdpmc_finish;
        mera.source = "RDPMC_perf";
        return;
      }
    }
#endif /* #T1HA_IA32_AVAILABLE */
    if (probe(clock_perf, clock_perf) == 0)
      perf_available = true;
  }
#else
#define perf_available false
#endif /* __NR_perf_event_open */

#if T1HA_IA32_AVAILABLE && !defined(__native_client__)
  fetch_cpu_features();
  if (ia32_cpu_features.basic.edx & (1 << 4)) {
    mera.convert = convert_1to1;
    mera.units = "clk";
    if (probe(clock_rdpmc_start, clock_rdpmc_finish) == 0) {
      mera.start = clock_rdpmc_start;
      mera.finish = clock_rdpmc_finish;
      mera.source = "RDPMC_40000001";
      mera.flags = timestamp_clock_stable | timestamp_clock_cheap;
      return;
    }

    mera.flags = timestamp_clock_stable | timestamp_clock_cheap;
    if (ia32_cpu_features.extended_80000007.edx & (1 << 8)) {
      /* The TSC rate is invariant, i.e. not a CPU cycles! */
      mera.flags -= timestamp_clock_stable;
      mera.units = "tick";
    }

    if (!perf_available || (mera.flags & timestamp_clock_stable)) {
      if ((ia32_cpu_features.extended_80000001.edx & (1 << 27)) &&
          probe(clock_rdtscp_start, clock_rdtscp_fihish) == 0) {
        mera.start = clock_rdtscp_start;
        mera.finish = clock_rdtscp_fihish;
        mera.source = "RDTSCP";
        return;
      }
      if (probe(clock_rdtsc_start, clock_rdtsc_finish)) {
        mera.start = clock_rdtsc_start;
        mera.finish = clock_rdtsc_finish;
        mera.source = "RDTSC";
        return;
      }
    }
  }
#endif /* T1HA_IA32_AVAILABLE */

#if __NR_perf_event_open
  if (perf_available) {
    mera.start = mera.finish = clock_perf;
    mera.convert = convert_1to1;
    mera.units = "clk";
    mera.source = "PERF_COUNT_HW_CPU_CYCLES";
    mera.flags = timestamp_clock_stable;
    return;
  }
#endif /* __NR_perf_event_open */

  mera.start = mera.finish = clock_fallback;
  mera.convert = convert_fallback;
  mera.units = UNITS;
  mera.source = SOURCE;
  mera.flags = FLAGS;
}

static unsigned fuse_timestamp(timestamp_t *unused) {
  (void)unused;
  abort();
  return 0;
}

static double fuse_convert(timestamp_t unused) {
  (void)unused;
  abort();
  return 0;
}

mera_t mera = {fuse_timestamp, fuse_timestamp, fuse_convert,
               "void",         "none",         false};
