#include <stdint.h>

#include "codec.h"
#include "bcrypt-ext.h"

unsigned char BF_itoa64[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
uint8_t BF_atoi64[] = {
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99,  0,  1,
  54, 55, 56, 57, 58, 59, 60, 61,   62, 63, 99, 99, 99, 99, 99, 99,

  99,  2,  3,  4,  5,  6,  7,  8,    9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,   25, 26, 27, 99, 99, 99, 99, 99,
  99, 28, 29, 30, 31, 32, 33, 34,   35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50,   51, 52, 53, 99, 99, 99, 99, 99,

  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,

  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99,
  99, 99, 99, 99, 99, 99, 99, 99,   99, 99, 99, 99, 99, 99, 99, 99
};

#define BF_safe_atoi64(dst, src) do { \
  uint32_t tmp = (unsigned char)(src); \
  tmp = BF_atoi64[tmp]; \
  if (tmp > 63) { return -1; } \
  (dst) = tmp; \
} while(0);

#pragma GCC visibility push(internal)
inline int BF_decode(BF_word *dst, const char *src, int size) {
  unsigned char *dptr = (unsigned char *)dst;
  unsigned char *end = dptr + size;
  const unsigned char *sptr = (const unsigned char *)src;
  unsigned int c1, c2, c3, c4;

  do {
    BF_safe_atoi64(c1, *sptr++);
    BF_safe_atoi64(c2, *sptr++);
    *dptr++ = (c1 << 2) | ((c2 & 0x30) >> 4);
    if (dptr >= end) break;

    BF_safe_atoi64(c3, *sptr++);
    *dptr++ = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2);
    if (dptr >= end) break;

    BF_safe_atoi64(c4, *sptr++);
    *dptr++ = ((c3 & 0x03) << 6) | c4;
  } while (dptr < end);

  return 0;
}

void BF_encode(char *dst, const BF_word *src, int size) {
  const unsigned char *sptr = (const unsigned char *)src;
  const unsigned char *end = sptr + size;
  unsigned char *dptr = (unsigned char *)dst;
  unsigned int c1, c2;

  do {
    c1 = *sptr++;
    *dptr++ = BF_itoa64[c1 >> 2];
    c1 = (c1 & 0x03) << 4;
    if (sptr >= end) {
      *dptr++ = BF_itoa64[c1];
      break;
    }

    c2 = *sptr++;
    c1 |= c2 >> 4;
    *dptr++ = BF_itoa64[c1];
    c1 = (c2 & 0x0f) << 2;
    if (sptr >= end) {
      *dptr++ = BF_itoa64[c1];
      break;
    }

    c2 = *sptr++;
    c1 |= c2 >> 6;
    *dptr++ = BF_itoa64[c1];
    *dptr++ = BF_itoa64[c2 & 0x3f];
  } while (sptr < end);
}

#pragma GCC visibility pop
