#define _GNU_SOURCE
#include "config.h"
#include "memzero.h"

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <assert.h>

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAS_GETRANDOM
#include <sys/random.h>
#else
#endif

#include "bcrypt-ext.h"
#include "codec.h"
#include "blake2b.h"

#define LIMB_T unsigned long
#define LIMB_SIZE (sizeof(LIMB_T))
#define LIMB_BITS (LIMB_SIZE*8)

#define BX_WKBYTES   32
#define BX_MACBYTES  16
#define BX_AEADBYTES (BX_WKBYTES+BX_MACBYTES)

extern BF_ctx BF_init_state;
extern BF_word BF_magic_w[6];
extern unsigned char BF_itoa64[];
extern uint8_t BF_atoi64[];

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

struct BF_data {
  BF_ctx ctx;
  BF_key expanded_key;
  BF_word workfactor;
  const char *setting;
  union {
    BF_word salt[4];
    BF_word output[6];
  } binary;
};

/* ChaCha20(b64d("PPkToMEmd9+wpO1GboJ1xQJKSsmbWDSJredh8EDC8DI="), 0, 0) */
static const uint8_t PERS_ENC[16] = {160,170,102,34,71,212,102,21,111,136,
89,185,166,163,227,234};

/* ChaCha20(b64d("q2UmpC+dwSBKgyDo8P48DxO0TbIUcyYT7UjMnrni7kE="), 0, 0) */
static const uint8_t PERS_MAC[16] = {143,107,112,154,242,226,17,10,134,95,
128,159,86,14,22,7};

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
{ \
  BF_word *ptr; \
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
    BF_ENCRYPT(P, S, L, R, A, B, C, D); \
    *(ptr - 2) = L; \
    *(ptr - 1) = R; \
  } while (ptr < &(S)[3][0xFF]); \
}

#define BF_iter(Q, L, R, A, B, C, D) \
{ \
  for (int i = 0; i < BF_N + 2; i += 2) { \
    Q->ctx.P[i] ^= Q->expanded_key[i]; \
    Q->ctx.P[i + 1] ^= Q->expanded_key[i + 1]; \
  } \
\
  int done = 0; \
  do { \
    BF_body(Q->ctx.P, Q->ctx.S, L, R, A, B, C, D); \
    if (done) break; \
    done = 1; \
\
    A = Q->binary.salt[0]; \
    B = Q->binary.salt[1]; \
    C = Q->binary.salt[2]; \
    D = Q->binary.salt[3]; \
    for (int i = 0; i < BF_N; i += 4) { \
      Q->ctx.P[i] ^= A; \
      Q->ctx.P[i + 1] ^= B; \
      Q->ctx.P[i + 2] ^= C; \
      Q->ctx.P[i + 3] ^= D; \
    } \
    Q->ctx.P[16] ^= A; \
    Q->ctx.P[17] ^= B; \
  } while (1); \
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#define BILLION 1000000000ULL;
static uint64_t getns() {
  uint64_t ns;
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  ns  = ts.tv_nsec;
  ns += ts.tv_sec * BILLION;
  return ns;
}

static uint64_t fstons(double s) {
  double ns = s * 1e9;
  return (uint64_t)ns;
}
#pragma GCC diagnostic pop

// decrement unsigned 128 bit integer
static inline int uint128_dec(LIMB_T n[16/LIMB_SIZE]) {
  if (n[0] == 1) {
    for (unsigned i = 1;;) {
      if (i == ((16/LIMB_SIZE)-1)) {
        if (n[i] == 0) return n[0] = 0;
        break;
      } else if (n[i++] != 0) {
        break;
      }
    }
  }

  for (unsigned i = 0; i < (16/LIMB_SIZE); ++i) {
    if (n[i] > 0) {
      n[i] -= 1;
      return 1;
    } else if (n[i] == 0) {
      n[i] = ~((LIMB_T)0);
    }
  }

  return -1;
}


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

// set unsigned 128 bit integer to 2 to the x'th power
static int uint128_shl(LIMB_T n[16/LIMB_SIZE], int x) {
  if (x < 0 || x > 127) return -1;
  for (unsigned i = 0; i < (16/LIMB_SIZE); ++i) n[i] = 0;
  int bits = 8 * LIMB_SIZE;
  int word = x / bits;
  n[word] = 1 << (x & (bits - 1));
  return 0;
}

static int BF_crypt_init(struct BF_data *data, const uint8_t *key, const char *setting, BF_word min) {
  BF_word L, R;
  BF_word tmp1, tmp2, tmp3, tmp4;
  BF_word *ptr;

  if (setting[0] != '$' ||
      setting[1] != '2' ||
      (setting[2] != 'b' && setting[2] != 'y') ||
      setting[3] != '$' ||
      setting[4] < '0' || setting[4] > '9' ||
      setting[5] < '0' || setting[5] > '9' ||
      setting[6] != '$') {
    errno = EINVAL;
    return -1;
  }

  data->workfactor = (setting[4] - '0') * 10 + (setting[5] - '0');
  if (data->workfactor < min || BF_decode(data->binary.salt, &setting[7], 16)) {
    errno = EINVAL;
    return -1;
  }

  data->setting = setting;

  BF_htobe(data->binary.salt, 4);
  BF_set_key(key, data->expanded_key, data->ctx.P);
  memcpy(data->ctx.S, BF_init_state.S, sizeof(data->ctx.S));

  L = R = 0;
  for (int i = 0; i < BF_N + 2; i += 2) {
    L ^= data->binary.salt[i & 2];
    R ^= data->binary.salt[(i & 2) + 1];
    BF_ENCRYPT(data->ctx.P, data->ctx.S, L, R, tmp1, tmp2, tmp3, tmp4);
    data->ctx.P[i] = L;
    data->ctx.P[i + 1] = R;
  }

  ptr = data->ctx.S[0];
  do {
    ptr += 4;

    L ^= data->binary.salt[(BF_N + 2) & 3];
    R ^= data->binary.salt[(BF_N + 3) & 3];
    BF_ENCRYPT(data->ctx.P, data->ctx.S, L, R, tmp1, tmp2, tmp3, tmp4);
    *(ptr - 4) = L;
    *(ptr - 3) = R;

    L ^= data->binary.salt[(BF_N + 4) & 3];
    R ^= data->binary.salt[(BF_N + 5) & 3];
    BF_ENCRYPT(data->ctx.P, data->ctx.S, L, R, tmp1, tmp2, tmp3, tmp4);
    *(ptr - 2) = L;
    *(ptr - 1) = R;
  } while (ptr < &data->ctx.S[3][0xFF]);

  return 0;
}

static int BF_crypt_work(struct BF_data *data, int work) {
  BF_word L, R;
  BF_word tmp1, tmp2, tmp3, tmp4;

  if (work < 0) work = data->workfactor;

  if (work < (int)(LIMB_BITS)) {
    // iteration count fits in a standard variable
    LIMB_T n = ((LIMB_T)1) << work;

    do {
      BF_iter(data, L, R, tmp1, tmp2, tmp3, tmp4);
    } while (--n);
  } else {
    // uint128 support needed
    LIMB_T n[16/LIMB_SIZE];
    if (uint128_shl(n, work) != 0) return -1;

    do {
      BF_iter(data, L, R, tmp1, tmp2, tmp3, tmp4);
    } while (uint128_dec(n));
  }

  return 0;
}

static char *BF_crypt_output(struct BF_data *data, char *output, int size) {
  BF_word L, R;
  BF_word tmp1, tmp2, tmp3, tmp4;

  if (size < BF_HASH_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  for (int i = 0; i < 6; i += 2) {
    L = BF_magic_w[i];
    R = BF_magic_w[i + 1];

    for (int j = 0; j < 64; ++j) {
      BF_ENCRYPT(data->ctx.P, data->ctx.S, L, R, tmp1, tmp2, tmp3, tmp4);
    }

    data->binary.output[i] = L;
    data->binary.output[i + 1] = R;
  }

  memcpy(output, data->setting, BF_SETTING_LEN - 1);
  output[BF_SETTING_LEN - 1] = BF_itoa64[(int)BF_atoi64[(int)data->setting[BF_SETTING_LEN - 1]] & 0x30];
  BF_htobe(data->binary.output, 6);
  BF_encode(&output[BF_SETTING_LEN], data->binary.output, 23);
  output[BF_HASH_LEN] = '\0';

  return output;
}

static char *BF_crypt_kwk_output(struct BF_data *data, char *output, int size, uint8_t kwk[BLAKE2B_KEYBYTES]) {
  BF_word *S = (BF_word *)data->ctx.S;
  BF_htobe(S, 4*256);
  // it should not be possible for this to fail...
  int ret = blake2b_simple(kwk, BLAKE2B_KEYBYTES, S, sizeof(BF_word)*4*256);
  assert(ret == 0);
  BF_betoh(S, 4*256);

  return BF_crypt_output(data, output, size);
}

static int BF_crypt_wrap(const uint8_t kwk[BLAKE2B_KEYBYTES], char *output, int size, const uint8_t ext[BX_WKBYTES]) {
  if (size < BF_EXT_LEN + 1) {
    errno = ERANGE;
    return -1;
  }

  blake2b_param P[1];
  blake2b_state S[1];
  BF_word wrapped[12];
  // ciphertext || auth tag
  uint8_t *ct = ((uint8_t *)(wrapped));
  uint8_t *mac = ((uint8_t *)(wrapped)) + BX_WKBYTES;

  blake2b_param_new(P);

  // keystream = blake2b(key = kwk, pers = [enc], data = pwhash)
  blake2b_param_set(P, BLAKE2B_PERSONAL, PERS_ENC, sizeof(PERS_ENC));
  blake2b_init(S, P, BX_WKBYTES, kwk, BLAKE2B_KEYBYTES);
  blake2b_update(S, output, BF_HASH_LEN);
  blake2b_final(S, ct, BX_WKBYTES);
  // ciphertext = plaintext xor keystream (in place)
  for (int i = 0; i < BX_WKBYTES; ++i) ct[i] ^= ext[i];

  // auth tag = blake2b(key = kwk, pers = [mac], data = pwhash || ciphertext)
  blake2b_param_set(P, BLAKE2B_PERSONAL, PERS_MAC, sizeof(PERS_MAC));
  blake2b_init(S, P, BX_MACBYTES, kwk, BLAKE2B_KEYBYTES);
  blake2b_update(S, output, BF_HASH_LEN);
  blake2b_update(S, ct, BX_WKBYTES);
  blake2b_final(S, mac, BX_MACBYTES);

  // encode wrapped data and append to pwhash
  output[BF_HASH_LEN] = '$';
  BF_letoh(wrapped, 12);
  BF_encode(output+BF_HASH_LEN+1, (BF_word *)wrapped, 48);
  output[BF_EXT_LEN] = '\0';

  memzero(wrapped, 48);

  return 0;
}

static int BF_crypt_unwrap(const uint8_t kwk[BLAKE2B_KEYBYTES], const char *input, uint8_t ext[BX_WKBYTES]) {
  blake2b_param P[1];
  blake2b_state S[1];
  BF_word wrapped[12];
  uint8_t ks[BX_WKBYTES];
  uint8_t chk[BX_MACBYTES];

  // decode wrapped data from pwhash
  BF_decode((BF_word *)wrapped, input+BF_HASH_LEN+1, 48);
  BF_htole(wrapped, 12);

  // ciphertext || auth tag
  uint8_t *ct = ((uint8_t *)(wrapped));
  uint8_t *mac = ((uint8_t *)(wrapped)) + BX_WKBYTES;

  blake2b_param_new(P);

  // auth tag = blake2b(key = kwk, pers = [mac], data = pwhash || ciphertext)
  blake2b_param_set(P, BLAKE2B_PERSONAL, PERS_MAC, sizeof(PERS_MAC));
  blake2b_init(S, P, BX_MACBYTES, kwk, BLAKE2B_KEYBYTES);
  blake2b_update(S, input, BF_HASH_LEN);
  blake2b_update(S, ct, BX_WKBYTES);
  blake2b_final(S, chk, BX_MACBYTES);

  // verify auth tag
  uint8_t v = 0;
  for (int i = 0; i < BX_MACBYTES; ++i) v |= mac[i] ^ chk[i];

  memzero(chk, BX_MACBYTES);

  if (v != 0) return -1;

  // keystream = blake2b(key = kwk, pers = [enc], data = pwhash)
  blake2b_param_set(P, BLAKE2B_PERSONAL, PERS_ENC, sizeof(PERS_ENC));
  blake2b_init(S, P, BX_WKBYTES, kwk, BLAKE2B_KEYBYTES);
  blake2b_update(S, input, BF_HASH_LEN);
  blake2b_final(S, ks, BX_WKBYTES);
  // plaintext = ciphertext xor keystream
  for (int i = 0; i < BX_WKBYTES; ++i) ext[i] = ct[i] ^ ks[i];

  memzero(ks, BX_WKBYTES);

  return 0;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static void *BF_crypt_clone(struct BF_data *dst, struct BF_data *src) {
  return memcpy(dst, src, sizeof(struct BF_data));
}
#pragma GCC diagnostic pop

static char *BF_crypt(struct BF_data *data, const uint8_t *key, const char *setting, char *output, int size, BF_word min) {
  if (BF_crypt_init(data, key, setting, min) != 0) return NULL;
  if (BF_crypt_work(data, -1) != 0) return NULL;
  return BF_crypt_output(data, output, size);
}

// hash password and generate a key wrapping key from the S array
static char *BF_crypt_kwk(struct BF_data *data, const uint8_t *key, const char *setting, char *output, int size, uint8_t kwk[BLAKE2B_KEYBYTES], BF_word min) {
  if (BF_crypt_init(data, key, setting, min) != 0) return NULL;
  if (BF_crypt_work(data, -1) != 0) return NULL;
  return BF_crypt_kwk_output(data, output, size, kwk);
}

static void magic(const char *setting, char *output, int size) {
  if (size >= 3) {
    output[0] = '*';
    output[1] = setting[0] == '*' && setting[1] == '0' ? '1' : '0';
    output[2] = '\0';
  }
}

static int csprng(void *out, int len) {
  int ret = -1;
  if (len < 0) return ret;

  // ideally, just use getrandom
  // TODO: add other OS API suppport
#ifdef HAS_GETRANDOM
  ret = getrandom(out, len, GRND_NONBLOCK);
#endif

  // fallback to reading /dev/urandom
  if (ret < len) {
    int fd;
    uint8_t *rand = (uint8_t *)out;
    errno = 0;
    if ((fd = open("/dev/urandom", O_RDONLY)) < 0) return -1;

    // keep reading until we have enough bytes
    ssize_t n;
    int total = 0;
    while (total < len) {
      for (;;) {
        errno = 0;
        n = read(fd, rand + total, sizeof(rand) - total);
        if (n == -1 && errno == EINTR) continue;
        break;
      }
      if (n < 1) return -1;

      total += n;
    }
    close(fd);
    errno = 0;
  }

  return ret;
}

// effectively wipes data structures as a side effect
static int BF_test(struct BF_data *data, int workfactor) {
  const uint8_t *test_key = (uint8_t *)"8b \xd0\xc1\xd2\xcf\xcc\xd8";
  const char *test_setting = "$2b$00$abcdefghijklmnopqrstuu";
  static const char * const test_hashes[] = {
    "i1D709vfamulimlGcq0qq3UvuUasvEa\0\x55", //_00
    "ea2P/XC0wqaYu8MS2U9Vei2nIfTJUHG\0\x55",
    "7df0f2n8vxhMUG.6KJna0H2yfJBqasm\0\x55",
    "Sg4bRvbyRqNr5QhS3wkDFU8qFWrWI32\0\x55",
    "CuG1542.TQQ5sV5blteEjyJX7.JFjVK\0\x55",
    "GfHEoDURu7Q6ifmsuE4jQVVoUgpARMa\0\x55", //_05
    "84jSgqqXY7rYooZCdSiV9EnuhEeXxfO\0\x55",
    "JtxJnHAGvqlOrCsRPO2UQiQp8zQzT0S\0\x55",
    "6MzYW9xr9OyWo4COY5UpcGM0a.hpPyW\0\x55",
    "zj7bMp.dwqQmiO7zj702f5m8Hbs3vZm\0\x55",
    "9DtqmZTtJIox/S2bpDWGgwgTHcKfifm\0\x55", //_10
    "XI1SmkIATHacbnoNQ7GO9k.YyPw.pBC\0\x55",
    "SWcBA2KWBjyvNwm2by31uzXFXdoMgPO\0\x55",
    "PEaJvk2yRxFWH5t4qfmN0chMvkX1Zhm\0\x55",
    "QelOzq9.YbfekxLQmOKuNhTTbKk3JWC\0\x55",
    "kMoCn3dYknJ3VE.Ueg2T5vewx8kQhsW\0\x55", //_15
    ".WKej21IvE2XA/19t2YaHSokxx34R82\0\x55",
    "fZSVVM72Cq6CQiSULKbjt1uXcNGX6cC\0\x55",
    "P/o66a8GOxiv3qJrPKhD.AiquuCzM1q\0\x55",
    "j2aXkPDDwRen9C42X4Tp36Ep.a7ba0q\0\x55",
    "fVMCs9o6Swdy3/lqgL.OYN5tCix20oC\0\x55", //_20
    "0Ur.qso.4D3aLpDrcZso61vO5uVC7v.\0\x55",
    "Twx/pVi.p8LJE/JnvIFI4sT7wNXNExW\0\x55",
    "IDdbhP2fL2aDzYxKOGbFT.Sdh9BI02i\0\x55",
    "/2x9atT8gIKUN43bB2yvsxgSpfR9jc6\0\x55",
    "nXpOZyQ1Si8bEQR2DDlI2QkPVaIIptq\0\x55", //_25
    "uugiiBtqNmUot/Tz8M1M56M9rBUgzTq\0\x55",
    "EhswxO8WJOKnpNMjatewDLR6KcQQ1jK\0\x55",
    "uuQIEdwdBEumQ3e1EZt7mk4r2aAdSkS\0\x55",
    "8nC9I3qqNkMuU4tjlhxxbaf6ea00qWe\0\x55",
    "FCKuTBCsuJCxOacfmhEUZeJxOjecmAm\0\x55", //_30
    "yt2VTnqPB6XjaqNkHFQoTECutHBUEji\0\x55",
    "hUkRUE01JLuxg7/PBEeH4GVNmz48T2O\0\x55",
  };
  const char *p;
  int ok;
  struct {
    char s[BF_SETTING_LEN + 1];
    char o[BF_HASH_LEN + 1 + 1 + 1];
  } buf;

#define N_HASHES (int)(sizeof(test_hashes) / sizeof(test_hashes[0]))
  if (workfactor < 0 || workfactor >= N_HASHES) {
    return -2;
  }
  const char *test_hash = test_hashes[workfactor];
#undef N_HASHES

  memcpy(buf.s, test_setting, sizeof(buf.s));
  buf.s[4] = '0' + workfactor / 10;
  buf.s[5] = '0' + workfactor % 10;
  memset(buf.o, 0x55, sizeof(buf.o));
  buf.o[sizeof(buf.o) - 1] = 0;
  p = BF_crypt(data, test_key, buf.s, buf.o, sizeof(buf.o) - (1 + 1), 0);
  ok = (p == buf.o &&
        !memcmp(p, buf.s, BF_SETTING_LEN) &&
        !memcmp(p + (BF_SETTING_LEN), test_hash, BF_BLOWFISH_LEN + 1 + 1 + 1));
  {
    const uint8_t *k = (uint8_t *)"\xff\xa3" "34" "\xff\xff\xff\xa3" "345";
    BF_key ye, yi;
    BF_set_key(k, ye, yi);
    ok = ok && ye[17] == 0x33343500;
  }

  return ok ? 0 : -1;
}

// encode setting string with random salt
static char *BF_salt(char *output, int size, int workfactor) {
  if (size < BF_SETTING_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  if (workfactor < 0 || workfactor > 99) {
    errno = EINVAL;
    return NULL;
  }

  uint8_t rand[16];
  if (csprng(rand, sizeof(rand)) < 0) {
    errno = errno || EIO;
    return NULL;
  }

  output[0] = '$';
  output[1] = '2';
  output[2] = 'b';
  output[3] = '$';
  output[4] = '0' + workfactor / 10;
  output[5] = '0' + workfactor % 10;
  output[6] = '$';

  BF_encode(&output[7], (const BF_word *)rand, 16);
  output[BF_SETTING_LEN] = '\0';

  return output;
}

static char *BF_bind(const uint8_t *key, char *output, int size, const uint8_t ext[BX_WKBYTES], int workfactor) {
  assert(size >= BF_EXT_LEN + 1);

  uint8_t kwk[64];
  struct BF_data data;
  char setting[BF_SETTING_LEN + 1], *retval = NULL;
  setting[0] = 0;

  if (BF_salt(setting, sizeof(setting), workfactor) == NULL) {
    errno = errno || EINVAL;
    return NULL;
  }

  magic(setting, output, size);

  if (ext != NULL) {
    retval = BF_crypt_kwk(&data, key, setting, output, size, kwk, 0);
    if (retval != NULL) {
      // wrap the ext key
      if (BF_crypt_wrap(kwk, output, size, ext) != 0) {
        errno = errno || EINVAL;
        retval = NULL;
      }
    }

    memzero(kwk, sizeof(kwk));
  } else {
    retval = BF_crypt(&data, key, setting, output, size, 4);
  }

  int saved_errno = errno;
  if (BF_test(&data, 0) == 0) {
    errno = saved_errno;
    return retval;
  }

  magic(setting, output, size);
  errno = errno || EINVAL;
  return retval;
}

/*************************
 *                       *
 *   EXPOSED FUNCTIONS   *
 *                       *
 *************************/

// XXX maybe getrusage timing?
int64_t bcrypt_bench(int workfactor) {
  int64_t d, best_d = INT64_MAX;
  uint64_t t, i = 0, start = getns();
  struct BF_data data;

  do {
    ++i;
    t = getns();
    int saved_errno = errno;
    if (BF_test(&data, workfactor) != 0) return -1;
    errno = saved_errno;
    d = getns() - t;
    if (d > 0 && d < best_d) best_d = d;
  } while (t - start < 1000000LL || i < 3);

  return best_d;
}

#define TARGET_TEST_MAX 8
#define TARGET_TEST_OK  4
int bcrypt_target(uint32_t msec) {
  int ratio_okay = 0;
  double ratio;
  int64_t nsec = (int64_t)msec * 1000000LL, curr, last;
  for (int repeat = 0; repeat < 12; ++repeat) {
    last = -1;
    for (int i = 1; i <= TARGET_TEST_MAX; ++i) {
      curr = bcrypt_bench(i);
      if (i > 3) {
        ratio = (double)curr / (double)last;
        if (ratio >= 1.9 && ratio <= 2.1) {
          ratio_okay += 1;
        } else if (i > TARGET_TEST_MAX - TARGET_TEST_OK) {
          break;
        } else {
          ratio_okay = 0;
        }

        if (ratio_okay >= TARGET_TEST_OK) {
          while (curr > nsec * 3) { curr /= 2; --i; }
          while (curr < (nsec * 3) / 4) { curr *= 2; ++i; }
          return i;
        }
      }

      last = curr;
    }
  }

  return -1;
}

int bcrypt_test() {
  int ret = 0;
  struct BF_data data;

  int saved_errno;
  for (int i = 0; i < 4; i += 1) {
    saved_errno = errno;
    if (BF_test(&data, i) == 0) {
      errno = saved_errno;
    } else {
      ret += 1;
      fprintf(stderr, "bcrypt_test: failed %d %d\n", i, errno);
    }
  }

  return ret;
}

int bcrypt_vectors() {
  int ret;
  struct BF_data data, clone;
  char output[80];

  if ((ret = bcrypt_test()) != 0) return ret;

  const uint8_t *test_key = (uint8_t *)"8b \xd0\xc1\xd2\xcf\xcc\xd8";
  const char *test_setting = "$2b$00$abcdefghijklmnopqrstuu";
  ret = BF_crypt_init(&data, test_key, test_setting, 0);
  for (int i = -1; i < 50;) {
    char filename[256];
    sprintf(filename, "bcrypt_midstate_%02d.dat", i+1);

    FILE *f;
    struct stat s;
    ret = stat(filename, &s);
    if (ret == 0) {
      fprintf(stderr, "loading %s\n", filename);
      f = fopen(filename, "r");
      const char *setting = data.setting;
      fread(&data, sizeof(data), 1, f);
      data.setting = setting;
      fclose(f);
      ++i;
    } else {
      ret = BF_crypt_work(&data, i++);
      if (ret != 0) {
        fprintf(stderr, "BF_crypt_work(%d) failed: %d\n", i-1, ret);
      }

      f = fopen(filename, "w");
      fwrite(&data, sizeof(data), 1, f);
      fclose(f);
    }

    BF_crypt_clone(&clone, &data);
    BF_crypt_output(&clone, output, sizeof(output));
    output[4] = '0' + i / 10;
    output[5] = '0' + i % 10;

    sprintf(filename, "bcrypt_test_vector_%02d.txt", i);
    f = fopen(filename, "w");
    fprintf(f, "%s\n", output);
    fclose(f);
    fprintf(stderr, "%s\n", output);
  }

  return ret;
}

int bcrypt_ext_test() {
  // TODO
  return bcrypt_test();
}

int bcrypt_ext_check(const uint8_t *key, const char *input, uint8_t ext[BX_WKBYTES]) {
  uint8_t kwk[64];
  int fail, saved_errno;
  char output[BF_HASH_LEN + 1], *retval;
  struct BF_data data;

  magic(input, output, sizeof(output));

  if (ext != NULL) {
    retval = BF_crypt_kwk(&data, key, input, output, sizeof(output), kwk, 0);
    fail = BF_crypt_unwrap(kwk, input, ext);
    memzero(kwk, sizeof(kwk));
  } else {
    fail = 0;
    retval = BF_crypt(&data, key, input, output, sizeof(output), 0);
  }

  saved_errno = errno;
  if (BF_test(&data, 0) == 0) {
    errno = saved_errno;
    char v = (fail == 0 ? 0 : 1);
    for (int i = 0; i < BF_HASH_LEN; ++i) v |= input[i] ^ output[i];
    if (retval != NULL && v == 0) return 1;
  }

  return 0;
}


char *bcrypt_ext_create(const uint8_t *key, char *output, int size, uint8_t ext[BX_WKBYTES], int workfactor) {
  if (size < BF_EXT_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  // generate random value for the wrapped key
  if (csprng(ext, BX_WKBYTES) < BX_WKBYTES) {
    errno = errno || EIO;
    return NULL;
  }

  return BF_bind(key, output, size, ext, workfactor);
}

char *bcrypt_ext_bind(const uint8_t *key, char *output, int size, const uint8_t ext[BX_WKBYTES], int workfactor) {
  if (size < BF_EXT_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  return BF_bind(key, output, size, ext, workfactor);
}

char *bcrypt_ext_rekey(const uint8_t *old_key, const uint8_t *new_key, char *io, int size, int new_workfactor) {
  if (size < BF_EXT_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  int workfactor;
  uint8_t ext[BX_WKBYTES];

  if (new_workfactor < 0) {
    workfactor = (io[4] - '0') * 10 + (io[5] - '0');
  } else {
    workfactor = new_workfactor;
  }

  if (bcrypt_ext_check(old_key, io, ext) != 1) {
    char setting[2] = { 0, 0 };
    magic(setting, io, size);
    errno = EINVAL;
    return NULL;
  }

  return BF_bind(new_key, io, size, ext, workfactor);
}

int bcrypt_check(const uint8_t *key, const char *input) {
  return bcrypt_ext_check(key, input, NULL);
}

char *bcrypt_create(const uint8_t *key, char *output, int size, int workfactor) {
  if (size < BF_HASH_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  return BF_bind(key, output, size, NULL, workfactor);
}
