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

#include "bench.h"
#include "../src/t1ha_bits.h"
#include <time.h>

static double measure(uint64_t (*hash)(const void *, size_t, uint64_t),
                      const void *data, unsigned len, uint64_t seed) {
  const time_t timeout_fuse = time(NULL);
  unsigned hash_loops = 1;
  unsigned retry_count = 0, restart_count = 0;

  timestamp_t overhead_best = INT64_MAX;
  timestamp_t overhead_gate = 0;
  unsigned overhead_loops_max = 0;

  restart_count -= 1;
restart_top:;
  timestamp_t overhead_sum = 0;
  unsigned overhead_total_count = 0;
  unsigned overhead_best_count = 1;
  unsigned overhead_worthless_loops = 0;
  unsigned overhead_accounted_loops = 0;

restart_middle:;
  timestamp_t hash_best = INT64_MAX;
  timestamp_t hash_gate = 0;
  unsigned tail_loops_max = 0;

restart_bottom:;
  timestamp_t hash_brutto_sum = 0;
  unsigned hash_overhead_count = 0;
  unsigned hash_best_count = 1;
  unsigned hash_total_count = 0;
  unsigned hash_worthless_loops = 0;
  unsigned hash_accounted_loops = 0;
  unsigned stable = 0;
  restart_count += 1;

  retry_count -= 1;
retry:
  retry_count += 1;

  while (true) {
    // measure the overhead of measurement
    unsigned coreid;
    {
      // wait for edge of tick
      timestamp_t snap, start, finish;
      coreid = mera.start(&snap);
      do {
        if (unlikely(coreid != mera.start(&start) || snap > start))
          goto retry;
      } while (snap == start);

      // first iteration
      unsigned loops = 1;
      if (unlikely(coreid != mera.finish(&finish) || start > finish))
        goto retry;

      // loop until end of tick
      while (start == finish) {
        loops += 1;
        if (unlikely(coreid != mera.start(&snap) || start > snap))
          goto retry;
        if (unlikely(coreid != mera.finish(&finish) || snap > finish))
          goto retry;
      }
      const timestamp_t elapsed = finish - start;
      if (unlikely(overhead_best > elapsed || overhead_loops_max < loops)) {
        if (overhead_best > elapsed) {
          overhead_gate = overhead_best + (overhead_best - elapsed + 1) / 2;
          if (overhead_gate > elapsed * 129 / 128)
            overhead_gate = elapsed * 129 / 128;
          if (overhead_gate < elapsed * 1025 / 1024 + 1)
            overhead_gate = elapsed * 1025 / 1024 + 1;
          overhead_best = elapsed;
        }
        overhead_loops_max =
            (overhead_loops_max > loops) ? overhead_loops_max : loops;
        goto restart_top;
      } else if (likely(elapsed <= overhead_gate &&
                        loops + 1 >= overhead_loops_max)) {
        if (elapsed == overhead_best && loops == overhead_loops_max)
          overhead_best_count += 1;
        overhead_sum += elapsed;
        overhead_total_count += loops;
        overhead_accounted_loops += 1;
      } else {
        overhead_worthless_loops += 1;
      }
    }

    // measure the hash
    if (hash) {
      // wait for edge of tick
      timestamp_t snap, start, finish;
      if (unlikely(coreid != mera.start(&snap)))
        goto retry;
      do {
        if (unlikely(coreid != mera.start(&start) || snap > start))
          goto retry;
      } while (snap == start);

      unsigned loops = 0;
      do
        hash(data, len, seed);
      while (++loops < hash_loops);

      loops = 1;
      if (unlikely(coreid != mera.finish(&finish) || snap > finish))
        goto retry;

      // wait for next tick
      while (true) {
        if (unlikely(coreid != mera.start(&snap) || finish > snap))
          goto retry;
        if (finish != snap)
          break;
        if (unlikely(coreid != mera.finish(&snap) || finish > snap))
          goto retry;
        if (finish != snap)
          break;
        loops += 1;
      }

      const timestamp_t elapsed = finish - start;
      if (unlikely(hash_best > elapsed ||
                   (hash_best == elapsed && tail_loops_max < loops))) {
        if (hash_best > elapsed) {
          hash_gate = hash_best + (hash_best - elapsed + 1) / 2;
          if (hash_gate > elapsed * 129 / 128)
            hash_gate = elapsed * 129 / 128;
          if (hash_gate < elapsed * 1025 / 1024 + 1)
            hash_gate = elapsed * 1025 / 1024 + 1;
          hash_best = elapsed;
        }
        tail_loops_max = loops;
        goto restart_bottom;
      } else if (likely(elapsed <= hash_gate &&
                        (tail_loops_max - loops /* overflow is ok */) < 2)) {
        if (elapsed == hash_best && loops == tail_loops_max)
          hash_best_count += 1;
        hash_total_count += hash_loops;
        hash_brutto_sum += elapsed;
        hash_overhead_count += loops;
        hash_accounted_loops += 1;
      } else {
        hash_worthless_loops += 1;
      }
    }

    // make a checkpoint
    if (unlikely((++stable & 1023) == 0)) {
      if (hash) {
        const timestamp_t target = 1042 + overhead_best * overhead_loops_max;
        if (hash_best < target) {
          hash_loops += hash_loops;
          goto restart_middle;
        }
        if (hash_loops > 1 && hash_best > target * 4) {
          hash_loops >>= 1;
          goto restart_middle;
        }
      }

      const int enough4fuse_seconds = 9;
      const unsigned enough4best =
          (mera.flags & timestamp_clock_stable) ? 499 : 1999;
      const unsigned enough4avg =
          (mera.flags & timestamp_clock_stable) ? 4999 : 29999;
      const unsigned enough4bailout =
          (mera.flags & timestamp_clock_cheap) ? 99999 : 59999;

      const bool enough4overhead =
          overhead_best_count > enough4best ||
          overhead_accounted_loops > enough4avg ||
          overhead_worthless_loops > enough4bailout ||
          time(NULL) - timeout_fuse > enough4fuse_seconds;

      const bool enough4hash = hash_best_count > enough4best ||
                               hash_accounted_loops > enough4avg ||
                               hash_worthless_loops > enough4bailout ||
                               time(NULL) - timeout_fuse > enough4fuse_seconds;

      // calculate result
      if (enough4overhead && (!hash || enough4hash)) {
#define DEBUG_BENCH
#ifdef DEBUG_BENCH
        printf("\n### convergence: retries %u, restarts %u\n", retry_count,
               restart_count);
        printf("### mats: best %" PRIu64 ", gate %" PRIu64
               ", loops_max %u, best_count %u, "
               "accounted_loops %u, worthless_loops "
               "%u\n",
               (uint64_t)overhead_best, (uint64_t)overhead_gate,
               overhead_loops_max, overhead_best_count,
               overhead_accounted_loops, overhead_worthless_loops);
#endif /* DEBUG_BENCH */
        const double measured_overhead =
            (overhead_best_count > 2 || overhead_total_count < enough4avg / 2)
                ? mera.convert(overhead_best) / overhead_loops_max
                : mera.convert(overhead_sum) / overhead_total_count;
        if (!hash)
          return measured_overhead;

#ifdef DEBUG_BENCH
        printf("### hash: loops %u, best %" PRIu64 ", gate %" PRIu64
               ", tail_loops_max %u, best_count %u, "
               "accounted_loops %u, worthless_loops "
               "%u\n",
               hash_loops, (uint64_t)hash_best, (uint64_t)hash_gate,
               tail_loops_max, hash_best_count, hash_accounted_loops,
               hash_worthless_loops);
#endif /* DEBUG_BENCH */

        const double measured_hash =
            (hash_best_count > 2 || hash_total_count < enough4avg / 2)
                ? (mera.convert(hash_best) -
                   measured_overhead * tail_loops_max) /
                      hash_loops
                : (mera.convert(hash_brutto_sum) -
                   measured_overhead * hash_overhead_count) /
                      hash_total_count;
        return measured_hash;
      }
    }
  }
}

double bench_mats(void) { return measure(NULL, NULL, 0, 0); }

void bench(const char *caption,
           uint64_t (*hash)(const void *, size_t, uint64_t), const void *data,
           unsigned len, uint64_t seed) {

  printf("%-24s: ", caption);
  fflush(NULL);

  double value = measure(hash, data, len, seed);

  printf("%10.3f %s/hash, %6.3f %s/byte, %6.3f byte/%s\n\n\n", value,
         mera.units, value / len, mera.units, len / value, mera.units);
  fflush(NULL);
}
