#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "bcrypt-ext.h"

extern BF_ctx BF_init_state;
extern BF_word BF_magic_w[6];

// Magic IV for 64 Blowfish encryptions that we use to produce the 'ext key'
// The string is "RecompilingSuperciliousCynosuresQuickest" on big-endian.
/*
static BF_word BF_magic_ext_w[10] = {
  0x5265636F, 0x6D70696C, 0x696E6753, 0x75706572, 0x63696C69,
  0x6F757343, 0x796E6F73, 0x75726573, 0x51756963, 0x6B657374
};
*/

#if (defined(BF_SCALE) && BF_SCALE)
// Architectures which can shift addresses left by 2 bits with no extra cost
#define BF_ROUND(P, S, L, R, A, B, C, D, N) \
  A = L & 0xFF; \
  B = L >> 8; \
  B &= 0xFF; \
  C = L >> 16; \
  C &= 0xFF; \
  D = L >> 24; \
  A = S[3][A]; \
  B = S[2][B]; \
  C = S[1][C]  \
    + S[0][D]; \
  C ^= B; \
  R ^= P[N]; \
  C += A; \
  R ^= C;
#else
// Architectures with no complicated addressing modes supported
#define BF_INDEX(S, i) (*((BF_word *)(((unsigned char *)S) + (i))))
#define BF_ROUND(P, S, L, R, A, B, C, D, N) \
  A = L & 0xFF; \
  A <<= 2; \
  B = L >> 6; \
  B &= 0x3FC; \
  C = L >> 14; \
  C &= 0x3FC; \
  D = L >> 22; \
  D &= 0x3FC; \
  A = BF_INDEX(S[3], A); \
  B = BF_INDEX(S[2], B); \
  C = BF_INDEX(S[1], C)  \
    + BF_INDEX(S[0], D); \
  C ^= B; \
  R ^= P[N]; \
  C += A; \
  R ^= C;
#endif

// Encrypt one block.
STATIC_ASSERT((BF_N&1)==0);
#define BF_ENCRYPT(P, S, L, R, A, B, C, D) do { \
  L ^= P[0]; \
  STR_PRAGMA(GCC unroll BF_N) \
  for (int i = 0; i < BF_N;) { \
    BF_ROUND(P, S, L, R, A, B, C, D, ++i); \
    BF_ROUND(P, S, R, L, A, B, C, D, ++i); \
  } \
  D = R; \
  R = L; \
  L = D ^ P[BF_N + 1]; \
} while(0);

#define BF_body(P, S, L, R, A, B, C, D) \
  L = R = 0; \
  ptr = P; \
  do { \
    ptr += 2; \
    BF_ENCRYPT(P, S, L, R, A, B, C, D); \
    *(ptr - 2) = L; \
    *(ptr - 1) = R; \
  } while (ptr < &(P)[BF_N + 2]); \
\
  ptr = (S)[0]; \
  do { \
    ptr += 2; \
    BF_ENCRYPT; \
    *(ptr - 2) = L; \
    *(ptr - 1) = R; \
  } while (ptr < &(S)[3][0xFF]);

static void BF_set_key(const uint8_t *key, BF_key expanded, BF_key initial) {
  const uint8_t *ptr = key;

  BF_word tmp;

  for (int i = 0; i < BF_N + 2; i++) {
    tmp = 0;

    // load 32 bit big endian value from password
    for (int j = 0; j < 4; j++) {
      tmp <<= 8;
      tmp |= *ptr;
      // wrap on null terminator
      ptr = *ptr ? ptr + 1 : key;
    }

    expanded[i] = tmp;
    initial[i] = BF_init_state.P[i] ^ tmp;
  }
}

static char *BF_crypt(const char *key, const char *setting, char *output, int size, BF_word min) {

}
