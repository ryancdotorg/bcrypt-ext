#include "codec.h"
#include "bcrypt-ext.h"

#pragma GCC visibility push(internal)
#define REP128(X) REP32(X), REP32(X), REP32(X), REP32(X)
#define REP32(X) REP8(X), REP8(X), REP8(X), REP8(X)
#define REP8(X) X, X, X, X, X, X, X, X
static const char lut85[85] = "0123456789ABCDEFGHIJKLMNOPQR"
"STUVWXYZabcdefghijklmnopqrstuvwxyz!#$&()*+,-;<=>?@^_`{|}~";
const unsigned char BF_itoa64[] = "./ABCDEFGHIJKLMN"
"OPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const unsigned char *SD_itoa64 = BF_itoa64 + 2;
uint8_t BF_atoi64[] = {
  REP32(99),            REP8(99),   99, 99, 99, 99, 99, 99,  0,  1,
  54, 55, 56, 57, 58, 59, 60, 61,   62, 63, 99, 99, 99, 99, 99, 99,
  99,  2,  3,  4,  5,  6,  7,  8,    9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24,   25, 26, 27, 99, 99, 99, 99, 99,
  99, 28, 29, 30, 31, 32, 33, 34,   35, 36, 37, 38, 39, 40, 41, 42,
  43, 44, 45, 46, 47, 48, 49, 50,   51, 52, 53, 99, 99, 99, 99, 99,
  REP128(99)
};
uint8_t SD_atoi64[] = {
  REP32(99),            REP8(99),   99, 99, 99, 62, 99, 99, 99, 63,
  52, 53, 54, 55, 56, 57, 58, 59,   60, 61, 99, 99, 99, 64, 99, 99,
  99,  0,  1,  2,  3,  4,  5,  6,    7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22,   23, 24, 25, 99, 99, 99, 99, 99,
  99, 26, 27, 28, 29, 30, 31, 32,   33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48,   49, 50, 51, 99, 99, 99, 99, 99,
  REP128(99)
};

#define safe_atoi64(dst, src) do { \
  uint32_t tmp = (unsigned char)(src); \
  tmp = atoi64[tmp]; \
  if (tmp > 63) { return -1; } \
  (dst) = tmp; \
} while(0);

static ssize_t _decode(void *dst, const char *src, size_t size, int standard) {
  const unsigned char *atoi64;
  unsigned char *end;
  unsigned char *dptr = (unsigned char *)dst;
  const unsigned char *sptr = (const unsigned char *)src;
  unsigned int remain, c1, c2, c3, c4;

  if (standard) {
    if ((remain = size % 4) == 1) return -1;
    atoi64 = SD_atoi64;
    end = dptr + (size - (remain ? 0 : 4));
  } else {
    remain = 0;
    atoi64 = BF_atoi64;
    end = dptr + size;
  }

  do {
    safe_atoi64(c1, *sptr++);
    safe_atoi64(c2, *sptr++);
    *dptr++ = (c1 << 2) | ((c2 & 0x30) >> 4);
    if (dptr >= end) break;

    safe_atoi64(c3, *sptr++);
    *dptr++ = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2);
    if (dptr >= end) break;

    safe_atoi64(c4, *sptr++);
    *dptr++ = ((c3 & 0x03) << 6) | c4;
  } while (dptr < end);

  if (standard) {
    // handle potentially padded base64
    while (remain == 0) {
      safe_atoi64(c1, *sptr++);
      safe_atoi64(c2, *sptr++);
      *dptr++ = (c1 << 2) | ((c2 & 0x30) >> 4);
      if (sptr[0] == '=' && sptr[1] == '=') break;

      safe_atoi64(c3, *sptr++);
      *dptr++ = ((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2);
      if (*sptr == '=') break;

      safe_atoi64(c4, *sptr++);
      *dptr = ((c3 & 0x03) << 6) | c4;
    }

    // calculate bytes decoded
    return (uintptr_t)dptr - (uintptr_t)dst;
  } else {
    return 0;
  }
}

int BF_decode(BF_word *dst, const char *src, int size) {
  return _decode(dst, src, size, 0);
}

ssize_t b64_decode(void *dst, const char *src, size_t size) {
  return _decode(dst, src, size, 1);
}

static ssize_t _encode(char *dst, const void *src, size_t size, int standard) {
  const unsigned char *itoa64 = standard ? SD_itoa64 : BF_itoa64;
  const unsigned char *sptr = (const unsigned char *)src;
  const unsigned char *end = sptr + size;
  unsigned char *dptr = (unsigned char *)dst;
  unsigned int c1, c2;

  do {
    c1 = *sptr++;
    *dptr++ = itoa64[c1 >> 2];
    c1 = (c1 & 0x03) << 4;
    if (sptr >= end) {
      *dptr++ = BF_itoa64[c1];
      if (standard) { *dptr++ = '='; *dptr++ = '='; }
      break;
    }

    c2 = *sptr++;
    c1 |= c2 >> 4;
    *dptr++ = itoa64[c1];
    c1 = (c2 & 0x0f) << 2;
    if (sptr >= end) {
      *dptr++ = BF_itoa64[c1];
      if (standard) { *dptr++ = '='; }
      break;
    }

    c2 = *sptr++;
    c1 |= c2 >> 6;
    *dptr++ = itoa64[c1];
    *dptr++ = itoa64[c2 & 0x3f];
  } while (sptr < end);

  // null terminate in standard mode
  if (standard) *dptr = '\0';

  // calculate bytes encoded
  return (uintptr_t)dptr - (uintptr_t)dst;
}

void BF_encode(char *dst, const BF_word *src, int size) {
  _encode(dst, src, size, 0);
}

ssize_t b64_encode(char *dst, size_t dst_sz, const void *src, size_t src_sz) {
  size_t needed = ((src_sz + 2) / 3) * 4 + 1;
  if (needed > dst_sz) return -1;
  return _encode(dst, src, src_sz, 1);
}

ssize_t b85_encode(char *dst, size_t dst_sz, const void *src, size_t src_sz) {
  const uint8_t *in = (uint8_t *)src;
  uint32_t block;
  int rem = src_sz % 4;
  size_t needed = (src_sz / 4) * 5 + (rem ? rem + 1 : 0) + 1;
  if (needed > dst_sz) return -1;
  size_t i = 0, o = 0, full = src_sz & (SIZE_MAX - 3);

  while (i < full) {
    block  = in[i++] <<  0;
    block |= in[i++] <<  8;
    block |= in[i++] << 16;
    block |= in[i++] << 24;

    dst[o++] = lut85[block % 85]; block /= 85;
    dst[o++] = lut85[block % 85]; block /= 85;
    dst[o++] = lut85[block % 85]; block /= 85;
    dst[o++] = lut85[block % 85]; block /= 85;
    dst[o++] = lut85[block];
  }

  block = 0;
  while (i < src_sz) {
    block = (block << 8) + in[i++];
  }

  switch (rem) {
    case 3:
      dst[o++] = lut85[block % 85]; block /= 85; /* fall through */
    case 2:
      dst[o++] = lut85[block % 85]; block /= 85; /* fall through */
    case 1:
      dst[o++] = lut85[block % 85]; block /= 85;
      dst[o++] = lut85[block % 85]; block /= 85; /* fall through */
  }

  dst[o] = '\0';
  return o;
}
#pragma GCC visibility pop
