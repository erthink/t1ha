t1ha
========================================
Fast Positive Hash, aka "Позитивный Хэш"
by [Positive Technologies](https://www.ptsecurity.com).

*The Future will Positive. Всё будет хорошо.*
[![Build Status](https://travis-ci.org/leo-yuriev/t1ha.svg?branch=devel)](https://travis-ci.org/leo-yuriev/t1ha)
[![Build status](https://ci.appveyor.com/api/projects/status/ptug5fl2ouxdo68h/branch/devel?svg=true)](https://ci.appveyor.com/project/leo-yuriev/t1ha/branch/devel)
[![CircleCI](https://circleci.com/gh/leo-yuriev/t1ha/tree/devel.svg?style=svg)](https://circleci.com/gh/leo-yuriev/t1ha/tree/devel)

## Briefly, it is a portable 64-bit hash function:
  1. Intended for 64-bit little-endian platforms, predominantly for x86_64,
     but portable and without penalties could run on any 64-bit CPU.
  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
     and all others portable hash-functions (which are not uses specific hardware tricks).
  3. Currently not suitable for cryptography.

Also pay attention to [Erlang](https://github.com/lemenkov/erlang-t1ha)
and [Golang](https://github.com/dgryski/go-t1ha) implementations.

********************************************************************************

# Usage
The `t1ha` library provides several terraced hash functions
with the dissimilar properties and for a different cases.

These functions briefly described below, see [t1ha.h](t1ha.h) for more API details.

Please, feel free to fill an issue or make pull request.


`t1ha0` = 64 bits, "Just Only Faster"
-------------------------------------

  Provides fast-as-possible hashing for current CPU, including 32-bit
  systems and engaging the available hardware acceleration.
  You can rest assured that t1ha0 faster than all other fast hashes
  (with comparable quality) so, otherwise we will extending and refine it time-to-time.

  On the other hand, without warranty that the hash result will be same
  for particular key on another machine or another version.
  Moreover, is deliberately known that the result will be different
  for systems with different bitness or endianness.
  Briefly, such hash-results and their derivatives, should be
  used only in runtime, but should not be persist or transferred
  over a network.

  Also should be noted, the quality of t1ha0() hashing is a subject
  for tradeoffs with performance. Therefore the quality and strength
  of t1ha0() may be lower than t1ha1(), especially on 32-bit targets,
  but then much faster.
  However, guaranteed that it passes all SMHasher tests.

  Internally t1ha0() selects most faster implementation for current CPU,
  for now these are includes:

 | Implementation          | Platform/CPU                           |
 | :---------------------- | :------------------------------------- |
 | `t1ha_ia32aes_avx()`    | x86 with AES-NI and AVX extensions     |
 | `t1ha_ia32aes_noavx()`  | x86 with AES-NI without AVX extensions |
 | `t1ha_32le()`           | 32-bit little-endian                   |
 | `t1ha_32be()`           | 32-bit big-endian                      |
 | `t1ha1_le()`            | 64-bit little-endian                   |
 | `t1ha1_be()`            | 32-bit big-endian                      |


`t1ha1` = 64 bits, fast portable hash
-------------------------------------

  The main generic version of "Fast Positive Hash" with reasonable quality
  for checksum, hash tables and thin fingerprinting. It is stable, e.g.
  returns same result on all architectures and CPUs.

  1. Speed with the reasonable quality of hashing.
  2. Efficiency on modern 64-bit CPUs, but not in a hardware.
  3. Strong as possible, until no penalties on performance.

  The main version is intended for little-endian systems and will runs
  slowly on big-endian. Therefore a dedicated big-endian version is also
  provided, but returns the different result than the main version.


`t1ha2` = 64 bits, little more attention for quality and strength
-----------------------------------------------------------------
  The next-step version of "Fast Positive Hash",
  but not yet finished and therefore not available.


`t1ha3` = 128 bits, fast non-cryptographic fingerprinting
---------------------------------------------------------
  The next-step version of "Fast Positive Hash",
  but not yet finished and therefore not available.


#### Planned: `t1ha4` = 128 bits, fast alternative for SipHash

#### Planned: `t1ha5` = 256 bits, fast insecure fingerprinting

#### Planned: `t1ha6` = 256 bits, Cryptographic

#### Planned: `t1ha7` = 256 bits, Cryptographic with reasonable resistance to acceleration on GPU and FPGA.


********************************************************************************

### Requirements and Portability:
  1. _t1ha_ designed for **modern 64-bit architectures**.
     But on the other hand, _t1ha_ doesn't require
     instructions specific to a particular architecture:
       - therefore t1ha could be used on any CPU for
         which compiler provides support 64-bit arithmetic.
       - but unfortunately _t1ha_ could be dramatically slowly
         on architectures without native 64-bit operations.
  2. This implementation of _t1ha_ requires **modern GNU C compatible compiler**,
     includes Clang/LLVM, or **Visual Studio 2015**.

#### Acknowledgement:
The _t1ha_ was originally developed by Leonid Yuriev (Леонид Юрьев)
for _The 1Hippeus project - zerocopy messaging in the spirit of Sparta!_


********************************************************************************

## Benchmarking and Testing
[_SMHasher_](https://github.com/aappleby/smhasher/wiki) is a wellknown
test suite designed to test the distribution, collision,
and performance properties of non-cryptographic hash functions.

_Reini Urban_ provides [extended version/fork of SMHasher](https://github.com/rurban/smhasher)
which integrates a lot of modern hash functions, including _t1ha_.

So, **the quality and speed of _t1ha_ can be easily checked with the following scenario:**

```
git clone https://github.com/rurban/smhasher
cd smhasher
cmake .
make
./SMHasher City64
./SMHasher metrohash64_1
./SMHasher xxHash64
...
./SMHasher t1ha
```

For properly performance please use at least GCC 5.4 or Clang 3.8,
at the worst Visual Studio 2015 (MSVC 19).

### Scores

Please take in account that the results is significantly depends on actual CPU, compiler version and CFLAGS.
The results below were obtained on:
 - CPU: `Intel(R) Core(TM) i7-6700K CPU`;
 - Compiler: `gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4)`;
 - CFLAGS: `-march=native -O3 -fPIC`;


#### The _SMALL KEYS_ case
Order by average Cycles per Hash for 1..31 bytes (less is better).

| Function              | MiB/Second | Cycles/Hash | Notes (quality, portability) |
| :-------------------- | ------------: | -------: | :--------------------------- |
_donothing_    	        |  15747227.36	|     6.00 | not a hash (just for reference)
_sumhash32_       	|     43317.86	|    16.69 | not a hash (just for reference)
FNV1a_YoshimitsuTRIAD	|     13000.49	|    24.96 | poor (100% bias, collisions, distrib)
crc64_hw        	|      7308.06	|    28.37 | poor (insecure, 100% bias, collisions, distrib), non-portable (SSE4.2)
crc32_hw        	|      5577.64	|    29.10 | poor (insecure, 100% bias, collisions, distrib), non-portable (SSE4.2)
NOP_OAAT_read64 	|      1991.31	|    30.46 | poor (100% bias, 2.17x collisions)
Crap8           	|      2743.80	|    32.50 | poor (2.42% bias, collisions, 2% distrib)
**t1ha_aes**        	|     **34636.42**	|    **33.03** | non-portable (AES-NI)
**t1ha**            	|     **12228.80**  |    **35.55** |
MUM             	|     10246.20	|    37.25 | non-portable (different result, machine specific)
Murmur2         	|      2789.89	|    38.37 | poor (1.7% bias, 81x coll, 1.7% distrib)
t1ha_32le       	|      5958.54	|    38.54 | alien (designed for 32-bit CPU)
t1ha_64be       	|      9321.23	|    38.29 | alien (designed for big-endian CPU)
lookup3         	|      1817.11	|    39.30 | poor (28% bias, collisions, 30% distrib)
t1ha_32be       	|      5873.45	|    39.81 | alien (designed for 32-bit big-endian CPU)
Murmur2C        	|      3655.60	|    42.68 | poor (91% bias, collisions, distrib)
fasthash64      	|      5578.06	|    43.42 |
Murmur2A        	|      2789.85	|    43.38 | poor (12.7% bias)
xxHash32        	|      5513.55	|    43.72 |
Murmur2B        	|      5578.21	|    44.13 | weak (1.8% bias, collisions, distrib)
fasthash32      	|      5381.46	|    45.50 |
cmetrohash64_1_optshort	|     11808.92	|    46.33 | _seems weak_ (likely cyclic collisions)
metrohash64_2   	|     12113.12	|    46.88 | _seems weak_ (likely cyclic collisions)
cmetrohash64_1  	|     12081.32	|    47.28 | _seems weak_ (likely cyclic collisions)
metrohash64_1   	|     12024.68	|    47.21 | _seems weak_ (likely cyclic collisions)
Murmur3F        	|      5473.62	|    47.37 |
superfast       	|      1860.25	|    47.45 | poor (91% bias, 5273.01x collisions, 37% distrib)
cmetrohash64_2  	|     12052.58	|    48.66 |
Murmur3A        	|      2232.00	|    48.16 |
City32          	|      5014.33	|    51.13 | far to perfect (2 minor collisions)
City64          	|     11041.72	|    51.77 |
metrohash64crc_2	|     20582.76	|    51.39 | _seems weak_ (likely cyclic collisions), non-portable (SSE4.2)
_sumhash_         	|      9668.13	|    51.31 | not a hash (just for reference)
metrohash64crc_1	|     21319.23	|    52.36 | weak (cyclic collisions), non-portable (SSE4.2)
PMurHash32      	|      2232.26	|    53.18 |
Murmur3C        	|      3719.22	|    54.05 |
bernstein       	|       921.43	|    55.17 | poor (100% bias, collisions, distrib)
xxHash64        	|     11123.15	|    56.17 |
Spooky32        	|     11464.20	|    59.45 |
City128         	|     12551.54	|    60.93 |
FarmHash64      	|     12145.36	|    60.12 | non-portable (SSE4.2)
Spooky128       	|     11735.99	|    60.45 | weak (collisions with 4bit diff)
Spooky64        	|     11820.20	|    60.39 |
CityCrc128      	|     14821.82	|    62.38 | non-portable (SSE4.2)
MicroOAAT       	|       826.32	|    62.06 | poor (100% bias, distrib)
metrohash128_1  	|     11063.78	|    66.58 | _seems weak_ (likely cyclic collisions)
metrohash128_2  	|     11465.18	|    66.72 | weak (cyclic collisions)
GoodOAAT        	|       930.18	|    68.24 |
metrohash128crc_1	|     21322.80	|    70.33 | _seems weak_ (likely cyclic collisions), non-portable (SSE4.2)
metrohash128crc_2	|     20990.70	|    70.40 | _seems weak_ (likely cyclic collisions), non-portable (SSE4.2)
farmhash64_c    	|     12033.13	|    71.30 | non-portable (SSE4.2)
sdbm            	|       695.29	|    71.76 | poor (100% bias, collisions, distrib)
FNV1a           	|       684.17	|    72.75 | poor (zeros, 100% bias, collisions, distrib)
FNV64           	|       697.67	|    72.70 | poor (100% bias, collisions, distrib)
FarmHash128     	|     12515.98	|    77.43 | non-portable (SSE4.2)
hasshe2         	|      2587.39	|    81.23 | poor (insecure, 100% bias, collisions, distrib), non-portable (SSE2)
_BadHash_         	|       558.14	|    87.87 | not a hash (just for reference)
x17             	|       551.99	|    89.24 | poor (99.98% bias, collisions, distrib)
JenkinsOOAT_perl	|       558.14	|    95.26 | poor (1.5-11.5% bias, 7.2x collisions)
farmhash128_c   	|     12709.06	|    96.42 | non-portable (SSE4.1)
MurmurOAAT      	|       465.12	|   107.61 | poor (collisions, 99.99% distrib)
JenkinsOOAT     	|       558.13	|   116.75 | poor (53.5% bias, collisions, distrib)
falkhash        	|      8909.54	|   124.48 | non-portable (AES-NI)
crc32           	|       342.27	|   142.06 | poor (insecure, 8589.93x collisions, distrib)
SipHash         	|       962.35	|   147.36 |
md5_32a         	|       433.03	|   508.98 |
sha1_32a        	|       531.44	|  1222.44 |


#### The _LARGE KEYS_ case
Order by hashing speed in Mi-bytes (2^20 = 1048576) per second for 262144-byte block (more is better).

| Function              | MiB/Second | Cycles/Hash | Notes (quality, portability) |
| :-------------------- | ------------: | -------: | :--------------------------- |
_donothing_    	        |  15747227.36	|     6.00 | not a hash (just for reference)
_sumhash32_       	|     43317.86	|    16.69 | not a hash (just for reference)
**t1ha_aes**        	|     **34636.42**	|    **33.03** | non-portable (AES-NI)
metrohash128crc_1	|     21322.80	|    70.33 | _seems weak_ (likely cyclic collisions), non-portable (SSE4.2)
metrohash64crc_1	|     21319.23	|    52.36 | _seems weak_ (cyclic collisions), non-portable (SSE4.2)
metrohash128crc_2	|     20990.70	|    70.40 | _seems weak_ (likely cyclic collisions), non-portable (SSE4.2)
metrohash64crc_2	|     20582.76	|    51.39 | _seems weak_ (likely cyclic collisions), non-portable (SSE4.2)
CityCrc128      	|     14821.82	|    62.38 | non-portable (SSE4.2)
FNV1a_YoshimitsuTRIAD	|     13000.49	|    24.96 | poor (100% bias, collisions, distrib)
farmhash128_c   	|     12709.06	|    96.42 | non-portable (SSE4.1)
City128         	|     12551.54	|    60.93 |
FarmHash128     	|     12515.98	|    77.43 | non-portable (SSE4.2)
**t1ha**            	|     **12228.80**  |    **35.55** |
FarmHash64      	|     12145.36	|    60.12 | non-portable (SSE4.2)
metrohash64_2   	|     12113.12	|    46.88 | _seems weak_ (likely cyclic collisions)
cmetrohash64_1  	|     12081.32	|    47.28 | _seems weak_ (likely cyclic collisions)
cmetrohash64_2  	|     12052.58	|    48.66 | _seems weak_ (likely cyclic collisions)
farmhash64_c    	|     12033.13	|    71.30 | non-portable (SSE4.2)
metrohash64_1   	|     12024.68	|    47.21 | _seems weak_ (likely cyclic collisions)
Spooky64        	|     11820.20	|    60.39 |
cmetrohash64_1_optshort	|     11808.92	|    46.33 | _seems weak_ (likely cyclic collisions)
Spooky128       	|     11735.99	|    60.45 | weak (collisions with 4-bit diff)
metrohash128_2  	|     11465.18	|    66.72 | weak (cyclic collisions)
Spooky32        	|     11464.20	|    59.45 |
xxHash64        	|     11123.15	|    56.17 |
metrohash128_1  	|     11063.78	|    66.58 | _seems weak_ (likely cyclic collisions)
City64          	|     11041.72	|    51.77 |
MUM             	|     10246.20	|    37.25 | non-portable (different result, machine specific)
_sumhash_         	|      9668.13	|    51.31 | not a hash (just for reference)
t1ha_64be       	|      9321.23	|    38.29 | alien (designed for big-endian CPU)
falkhash        	|      8909.54	|   124.48 | non-portable (AES-NI)
crc64_hw        	|      7308.06	|    28.37 | poor (insecure, 100% bias, collisions, distrib), non-portable (SSE4.2)
t1ha_32le       	|      5958.54	|    38.54 | alien (designed for 32-bit CPU)
t1ha_32be       	|      5873.45	|    39.81 | alien (designed for 32-bit big-endian CPU)
fasthash64      	|      5578.06	|    43.42 |
Murmur2B        	|      5578.21	|    44.13 | weak (1.8% bias, collisions, distrib)
crc32_hw        	|      5577.64	|    29.10 | poor (insecure, 100% bias, collisions, distrib), non-portable (SSE4.2)
xxHash32        	|      5513.55	|    43.72 |
Murmur3F        	|      5473.62	|    47.37 |
fasthash32      	|      5381.46	|    45.50 |
City32          	|      5014.33	|    51.13 | far to perfect (2 minor collisions)
Murmur3C        	|      3719.22	|    54.05 |
Murmur2C        	|      3655.60	|    42.68 | poor (91% bias, collisions, distrib)
Murmur2         	|      2789.89	|    38.37 | poor (1.7% bias, 81x coll, 1.7% distrib)
Murmur2A        	|      2789.85	|    43.38 | poor (12.7% bias)
Crap8           	|      2743.80	|    32.50 | poor (2.42% bias, collisions, 2% distrib)
hasshe2         	|      2587.39	|    81.23 | poor (insecure, 100% bias, collisions, distrib), non-portable (SSE2)
Murmur3A        	|      2232.00	|    48.16 |
PMurHash32      	|      2232.26	|    53.18 |
NOP_OAAT_read64 	|      1991.31	|    30.46 | poor (100% bias, 2.17x collisions)
superfast       	|      1860.25	|    47.45 | poor (91% bias, 5273.01x collisions, 37% distrib)
lookup3         	|      1817.11	|    39.30 | poor (28% bias, collisions, 30% distrib)
SipHash         	|       962.35	|   147.36 |
GoodOAAT        	|       930.18	|    68.24 |
bernstein       	|       921.43	|    55.17 | poor (100% bias, collisions, distrib)
MicroOAAT       	|       826.32	|    62.06 | poor (100% bias, distrib)
FNV64           	|       697.67	|    72.70 | poor (100% bias, collisions, distrib)
sdbm            	|       695.29	|    71.76 | poor (100% bias, collisions, distrib)
FNV1a           	|       684.17	|    72.75 | poor (zeros, 100% bias, collisions, distrib)
_BadHash_         	|       558.14	|    87.87 | not a hash (just for reference)
JenkinsOOAT     	|       558.13	|   116.75 | poor (53.5% bias, collisions, distrib)
JenkinsOOAT_perl	|       558.14	|    95.26 | poor (1.5-11.5% bias, 7.2x collisions)
x17             	|       551.99	|    89.24 | poor (99.98% bias, collisions, distrib)
sha1_32a        	|       531.44	|  1222.44 |
MurmurOAAT      	|       465.12	|   107.61 | poor (collisions, 99.99% distrib)
md5_32a         	|       433.03	|   508.98 |
crc32           	|       342.27	|   142.06 | poor (insecure, 8589.93x collisions, distrib)
