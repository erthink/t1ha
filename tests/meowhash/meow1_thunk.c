/* ========================================================================

   meow_example.cpp - basic usage example of the Meow hash
   (C) Copyright 2018 by Molly Rocket, Inc. (https://mollyrocket.com)

   See https://mollyrocket.com/meowhash for details.

   ======================================================================== */

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

//
// NOTE(casey): Step 1 - include an intrinsics header, then include meow_hash.h
//
// Meow relies on definitions for non-standard types (meow_u128, etc.) and
// intrinsics for various platforms. You can either include the supplied
// meow_intrinsics.h file that will define these for you with its best guesses
// for your platform, or for more control, you can define them all yourself to
// map to your own stuff.
//

#if defined(_MSC_VER)
#pragma warning(disable : 4201) /* nameless struct/union */
#endif

#if !defined(_MSC_VER) || _MSC_VER > 1910 || defined(_M_X64)

#include "meow_intrinsics.h" // NOTE(casey): Platform prerequisites for the Meow hash code (replace with your own, if you want)

#include "meow_hash.h" // NOTE(casey): The Meow hash code itself

#include <stdint.h>
uint64_t thunk_MeowHash1(const void *input, size_t length, uint64_t seed) {
  return MeowU64From(MeowHash1(seed, length, (void *)input));
}

#endif /* !defined(_MSC_VER) || _MSC_VER > 1910 || defined(_M_X64) */
