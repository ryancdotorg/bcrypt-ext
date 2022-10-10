#pragma once
#define _GNU_SOURCE

#include <stdint.h>
#include <endian.h>
#include <assert.h>

#define TRACE fprintf(stderr, "TRACE:%s:%s@%d %s (%d)\n", __FILE__, __func__, __LINE__, strerror(errno), errno)

#define STATIC_ASSERT(test) static_assert((test), "(" #test ")")

#define _STR(S) #S
#define STR(S) _STR(S)
#define _STR_PRAGMA(S) _Pragma(#S)
#define STR_PRAGMA(S) _STR_PRAGMA(S)

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

// $2b$08$sYO6EwKwhLMi/68nGAjf6uJ.8NxwnO9HLvEftl4dpcrXFpbAbl7wq
#define BF_PARAM_LEN 7
#define BF_SALT_LEN 22
#define BF_SETTING_LEN (BF_PARAM_LEN+BF_SALT_LEN)
#define BF_BLOWFISH_LEN 31
#define BF_WRAPPED_LEN 65
#define BF_HASH_LEN (BF_SETTING_LEN+BF_BLOWFISH_LEN)
#define BF_EXT_LEN (BF_HASH_LEN+BF_WRAPPED_LEN)

STATIC_ASSERT((BF_N&1)==0);

typedef struct {
  BF_word S[4][256];
  BF_key P;
} BF_ctx;

#define BF_htobe(ARRAY, COUNT) do { \
  static uint16_t one = 1; \
  uint8_t *little_endian = (uint8_t *)&one; \
  if (*little_endian) { \
    STR_PRAGMA(GCC unroll 16) \
    STR_PRAGMA(GCC ivdep) \
    for (int i = 0; i < COUNT; ++i) ARRAY[i] = htobe32(ARRAY[i]); \
  } \
} while(0);

#define BF_betoh(ARRAY, COUNT) do { \
  static uint16_t one = 1; \
  uint8_t *little_endian = (uint8_t *)&one; \
  if (*little_endian) { \
    STR_PRAGMA(GCC unroll 16) \
    STR_PRAGMA(GCC ivdep) \
    for (int i = 0; i < COUNT; ++i) ARRAY[i] = be32toh(ARRAY[i]); \
  } \
} while(0);

#define BF_htole(ARRAY, COUNT) do { \
  static uint16_t one = 256; \
  uint8_t *big_endian = (uint8_t *)&one; \
  if (*big_endian) { \
    STR_PRAGMA(GCC unroll 16) \
    STR_PRAGMA(GCC ivdep) \
    for (int i = 0; i < COUNT; ++i) ARRAY[i] = htole32(ARRAY[i]); \
  } \
} while(0);

#define BF_letoh(ARRAY, COUNT) do { \
  static uint16_t one = 256; \
  uint8_t *big_endian = (uint8_t *)&one; \
  if (*big_endian) { \
    STR_PRAGMA(GCC unroll 16) \
    STR_PRAGMA(GCC ivdep) \
    for (int i = 0; i < COUNT; ++i) ARRAY[i] = le32toh(ARRAY[i]); \
  } \
} while(0);

int bcrypt_test();
int64_t bcrypt_bench(int workfactor);
int bcrypt_target(uint32_t msec);

int bcrypt_check(const uint8_t *key, const char *input);
char *bcrypt_create(const uint8_t *key, char *output, int size, int workfactor);

int bcrypt_ext_test();
int bcrypt_ext_check(const uint8_t *key, const char *input, uint8_t *ext);
char *bcrypt_ext_create(const uint8_t *key, char *output, int size, uint8_t ext[32], int workfactor);
char *bcrypt_ext_rekey(const uint8_t *old_key, const uint8_t *new_key, char *data, int size, int new_workfactor);
