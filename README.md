t1ha
========================================
Fast Positive Hash, aka "Позитивный Хэш"
by [Positive Technologies](https://www.ptsecurity.ru)


### Briefly, it is a 64-bit Hash Function:
  1. For 64-bit platforms, in predominantly for x86_64.
  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash, etc.
  3. Not suitable for cryptography.


Please see [t1ha.c](t1ha.c#L171) for implementation details.


#### Acknowledgement:
The **t1ha** was originally developed by Leonid Yuriev for The 1Hippeus project.

_1Hippeus_ - zerocopy messaging in the spirit of Sparta!


## Benchmarking & Testing
```
git clone https://github.com/leo-yuriev/t1ha.git
cd t1ha
git checkout smhasher-rurban.t1ha
cmake .
make
./SMHasher City64
./SMHasher metrohash64_1
./SMHasher xxHash64
./SMHasher mum
...
./SMHasher t1ha
```
