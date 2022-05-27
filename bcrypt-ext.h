#pragma once
#define _GNU_SOURCE

#include <stdint.h>
#include <endian.h>
#include <assert.h>

#define STATIC_ASSERT(test) static_assert((test), "(" #test ")")

#define _STR(S) #S
#define STR(S) _STR(S)
#define _STR_PRAGMA(S) _Pragma(#S)
#define STR_PRGAGMA(S) _STR_PRAGMA(S)

// TODO: ARM?
#ifdef __i386__
#define BF_SCALE 1
#elif defined(__x86_64__) || defined(__alpha__) || defined(__hppa__)
#define BF_SCALE 1
#else
#define BF_SCALE 0
#endif

typedef uint32_t BF_word;
typedef int32_t BF_word_signed;

#define BF_N 16
typedef BF_word BF_key[BF_N + 2];

STATIC_ASSERT((BF_N&1)==0);

typedef struct {
  BF_word S[4][256];
  BF_key P;
} BF_ctx;

#define BF_htobe(ARRAY, COUNT) do { \
  static uint16_t one = 1; \
  uint8_t *little_endian = (uint8_t *)&one; \
  if (*little_endian) { \
    STR_PRAGMA(GCC unroll COUNT) \
    _Pragma("GCC ivdep") \
    for (int i = 0; i < COUNT; ++i) ARRAY[i] = htobe32(ARRAY[i]); \
  } \
} while(0);
