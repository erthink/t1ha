t1ha
========================================
Fast Positive Hash, aka "Позитивный Хэш"
by [Positive Technologies](https://www.ptsecurity.com).

*The Future will Positive. Всё будет хорошо.*
[![Build Status](https://travis-ci.org/leo-yuriev/t1ha.svg?branch=master)](https://travis-ci.org/leo-yuriev/t1ha)

### Briefly, it is a 64-bit Hash Function:
  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
     but without penalties could runs on any 64-bit CPU.
  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
     and all others which are not use specific hardware tricks.
  3. Not suitable for cryptography.


Please see [t1ha.c](t1ha.c) for implementation details.


#### Acknowledgement:
The _t1ha_ was originally developed by Leonid Yuriev (Леонид Юрьев)
for _The 1Hippeus project - zerocopy messaging in the spirit of Sparta!_


### Requirements and Portability:
  1. _t1ha_ designed for modern 64-bit architectures.
     But on the other hand, _t1ha_ doesn't uses any one tricks nor
     instructions specific to any particular architecture:
       - therefore t1ha could be used on any CPU for
         which GCC provides support 64-bit arithmetics.
       - but unfortunately _t1ha_ could be dramatically slowly
         on architectures without native 64-bit operations.
  3. This implementation of _t1ha_ requires modern GNU C compatible compiler,
     includes Clang/LLVM and Visual Studio 2015 (MSVC 19).


## Benchmarking and Testing
[_SMHasher_](https://github.com/aappleby/smhasher/wiki) is a wellknown test suite designed to test the distribution, collision, and performance properties of non-cryptographic hash functions.

_Reini Urban_ provides [extended version/fork of SMHasher](https://github.com/rurban/smhasher) which integrates a lot of modern hash functions, including _t1ha_.

So, **the quality and speed of _t1ha_ can be easily checked with the following scenario:**

```
git clone https://github.com/rurban/smhasher
cd smhasher
cmake .
make
./SMHasher City64
./SMHasher metrohash64_1
./SMHasher xxHash64
./SMHasher mum
...
./SMHasher t1ha
```

For properly performance please use at least GCC 5.4 or Clang 3.8, at the worst Visual Studio 2015 (MSVC 19).