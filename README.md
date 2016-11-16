t1ha
=========================================
Fast Positive Hash, aka "Позитивный Хэш"
by [Positive Technologies](https://www.ptsecurity.ru)


### Briefly, it is a 64-bit Hash Function:
  1. For 64-bit platforms, in predominantly for x86_64.
  2. 5-10% faster than City64 from Google:
      - with approximately the same quality,
      - but has bit more regular structure and less code size.
  3. Not suitable for cryptography.


Please see [t1ha.cc](t1ha.cc#L96) for implementation details.


### ACKNOWLEDGEMENT:
The **t1ha** was originally developed by Leonid Yuriev for The 1Hippeus project.

_1Hippeus_ - zerocopy messaging in the spirit of Sparta!
