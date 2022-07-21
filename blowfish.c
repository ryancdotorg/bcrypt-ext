#define _GNU_SOURCE
#include "config.h"

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>

#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef HAS_GETRANDOM
#include <sys/random.h>
#else
#endif

#include "bcrypt-ext.h"
#include "codec.h"
#include "blake2b.h"
#include "chachapoly.h"

#define LIMB_T unsigned long
#define LIMB_SIZE (sizeof(LIMB_T))
#define LIMB_BITS (LIMB_SIZE*8)

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

static inline int uint128_dec(LIMB_T n[16/LIMB_SIZE]) {
  if (n[0] == 1) {
    fprintf(stderr, "Last iteration? ");
    for (unsigned i = 1;; ++i) {
      if (i == ((16/LIMB_SIZE)-1)) {
        if (n[i] == 0) {
          n[0] = 0;
          fprintf(stderr, "Yes.\n");
          return 0;
        } else {
          break;
        }
      } else if (n[i] != 0) {
        break;
      }
    }
    fprintf(stderr, "No.\n");
  }

  for (unsigned i = 0; i < (16/LIMB_SIZE); ++i) {
    if (n[i] > 0xfffc || n[i] < 0x0004) {
      fprintf(stderr, "uint128_dec %d %016lx\n", i, n[i]);
    }
    if (n[i] > 0) {
      n[i] -= 1;
      return 1;
    } else if (n[i] == 0) {
      fprintf(stderr, "n[%d] == 0\n", i);
      if (i == ((16/LIMB_SIZE)-1)) {
        fprintf(stderr, "end\n");
        return 0;
      }
      n[i] = ~((LIMB_T)0);
      // next iteration
    }
  }

  return -1;
}

static inline int uint128_shl(LIMB_T n[16/LIMB_SIZE], int x) {
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

  if (work <= (int)(LIMB_BITS-1)) {
    LIMB_T n = 1 << work;
    fprintf(stderr, "doing work using  (%lu bits) %016lx\n", LIMB_BITS, n);
    do {
      BF_iter(data, L, R, tmp1, tmp2, tmp3, tmp4);
    } while (--n);
  } else {
    LIMB_T n[16/LIMB_SIZE];
    if (uint128_shl(n, work) != 0) return -1;
    fprintf(stderr, "doing work using uint128 emulation ");
    if (16/LIMB_SIZE == 2) {
      fprintf(stderr, "%016lx %016lx\n", n[0], n[1]);
    } else if (16/LIMB_SIZE == 4) {
      fprintf(stderr, "%08lx %08lx %08lx %08lx\n", n[0], n[1], n[2], n[3]);
    } else if (16/LIMB_SIZE == 8) {
      fprintf(stderr, "%04lx %04lx %04lx %04lx %04lx %04lx %04lx %04lx\n", n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
    } else if (16/LIMB_SIZE == 16) {
      fprintf(stderr, "%02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx\n", n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
    }
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

  memcpy(output, data->setting, 7 + 22 - 1);
  output[7 + 22 - 1] = BF_itoa64[(int)BF_atoi64[(int)data->setting[7 + 22 - 1]] & 0x30];
  BF_htobe(data->binary.output, 6);
  BF_encode(&output[7 + 22], data->binary.output, 23);
  output[BF_HASH_LEN] = '\0';

  return output;
}

static int BF_crypt_extkey(struct BF_data *data, uint8_t *output) {
  BF_word *S = (BF_word *)data->ctx.S;

  BF_htobe(S, 4*256);
  int ret = blake2b(output, 32, S, sizeof(BF_word)*4*256, NULL, NULL, 0);
  BF_betoh(S, 4*256);

  return ret;
}

static void *BF_crypt_clone(struct BF_data *dst, struct BF_data *src) {
  return memcpy(dst, src, sizeof(struct BF_data));
}

static char *BF_crypt(struct BF_data *data, const uint8_t *key, const char *setting, char *output, int size, BF_word min) {
  if (BF_crypt_init(data, key, setting, min) != 0) return NULL;
  if (BF_crypt_work(data, -1) != 0) return NULL;

  /*
  uint8_t extkey[32];
  BF_crypt_extkey(data, extkey);
  printf("extkey: ");
  for (int i = 0; i < 32; ++i) printf("%02x", extkey[i]);
  printf("\n");
  // */

  return BF_crypt_output(data, output, size);
}

static inline void magic(const char *setting, char *output, int size) {
  if (size >= 3) {
    output[0] = '*';
    output[1] = setting[0] == '*' && setting[1] == '0' ? '1' : '0';
    output[2] = '\0';
  }
}

static int csprng(void *out, int len) {
  int ret = -1;
  if (len < 0) return ret;

#ifdef HAS_GETRANDOM
  ret = getrandom(out, len, GRND_NONBLOCK);
#endif

  // fallback to reading /dev/urandom
  if (ret < len) {
    int fd;
    uint8_t *rand = (uint8_t *)out;
    errno = 0;
    if ((fd = open("/dev/urandom", O_RDONLY)) < 0) return -1;

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

static int BF_test(struct BF_data *data, int workfactor) {
  const uint8_t *test_key = (uint8_t *)"8b \xd0\xc1\xd2\xcf\xcc\xd8";
  const char *test_setting = "$2b$00$abcdefghijklmnopqrstuu";
  static const char * const test_hashes[] = {
    "i1D709vfamulimlGcq0qq3UvuUasvEa\0\x55", // 00
    "ea2P/XC0wqaYu8MS2U9Vei2nIfTJUHG\0\x55",
    "7df0f2n8vxhMUG.6KJna0H2yfJBqasm\0\x55",
    "Sg4bRvbyRqNr5QhS3wkDFU8qFWrWI32\0\x55",
    "CuG1542.TQQ5sV5blteEjyJX7.JFjVK\0\x55",
    "GfHEoDURu7Q6ifmsuE4jQVVoUgpARMa\0\x55", // 05
    "84jSgqqXY7rYooZCdSiV9EnuhEeXxfO\0\x55",
    "JtxJnHAGvqlOrCsRPO2UQiQp8zQzT0S\0\x55",
    "6MzYW9xr9OyWo4COY5UpcGM0a.hpPyW\0\x55",
    "zj7bMp.dwqQmiO7zj702f5m8Hbs3vZm\0\x55",
    "9DtqmZTtJIox/S2bpDWGgwgTHcKfifm\0\x55", // 10
    "XI1SmkIATHacbnoNQ7GO9k.YyPw.pBC\0\x55",
    "SWcBA2KWBjyvNwm2by31uzXFXdoMgPO\0\x55",
    "PEaJvk2yRxFWH5t4qfmN0chMvkX1Zhm\0\x55",
    "QelOzq9.YbfekxLQmOKuNhTTbKk3JWC\0\x55",
    "kMoCn3dYknJ3VE.Ueg2T5vewx8kQhsW\0\x55", // 15
    ".WKej21IvE2XA/19t2YaHSokxx34R82\0\x55",
    "fZSVVM72Cq6CQiSULKbjt1uXcNGX6cC\0\x55",
    "P/o66a8GOxiv3qJrPKhD.AiquuCzM1q\0\x55",
    "j2aXkPDDwRen9C42X4Tp36Ep.a7ba0q\0\x55",
    "fVMCs9o6Swdy3/lqgL.OYN5tCix20oC\0\x55", // 20
    "0Ur.qso.4D3aLpDrcZso61vO5uVC7v.\0\x55",
    "Twx/pVi.p8LJE/JnvIFI4sT7wNXNExW\0\x55",
    "IDdbhP2fL2aDzYxKOGbFT.Sdh9BI02i\0\x55",
    "/2x9atT8gIKUN43bB2yvsxgSpfR9jc6\0\x55",
    "nXpOZyQ1Si8bEQR2DDlI2QkPVaIIptq\0\x55", // 25
    "uugiiBtqNmUot/Tz8M1M56M9rBUgzTq\0\x55",
    "EhswxO8WJOKnpNMjatewDLR6KcQQ1jK\0\x55",
    "uuQIEdwdBEumQ3e1EZt7mk4r2aAdSkS\0\x55",
    "8nC9I3qqNkMuU4tjlhxxbaf6ea00qWe\0\x55",
    "FCKuTBCsuJCxOacfmhEUZeJxOjecmAm\0\x55", // 30
    "yt2VTnqPB6XjaqNkHFQoTECutHBUEji\0\x55",
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
  //printf("p(%p): %s\n", p, p);
  //printf("t(%p):                              %s\n", test_hash, test_hash);
  //printf("s(%p): %s\n", buf.s, buf.s);
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

int bcrypt_test() {
  int saved_errno, ret = 0;
  struct BF_data data, clone;
  char output[80];

  /*
  for (int i = 0; i < 12; i += 1) {
    saved_errno = errno;
    if (BF_test(&data, i) == 0) {
      errno = saved_errno;
    } else {
      ret += 1;
      fprintf(stderr, "bcrypt_test: failed %d %d\n", i, errno);
    }
  }

  if (ret) return ret;
  */

  struct chachapoly_ctx ccp;

  char wrapped_b64[66];
  BF_word wrapped[12];
  uint8_t kwk[32], key[32], uwk[32];
  for (int i = 0; i < 32; ++i) key[i] = i + 1;
  csprng(key, sizeof(key));

  const uint8_t *test_key = (uint8_t *)"8b \xd0\xc1\xd2\xcf\xcc\xd8";
  const char *test_setting = "$2b$00$abcdefghijklmnopqrstuu";
  ret = BF_crypt_init(&data, test_key, test_setting, 0);
  for (int i = -1; i < 50;) {
    ret = BF_crypt_work(&data, i++);
    if (ret != 0) {
      fprintf(stderr, "BF_crypt_work(%d) failed: %d\n", i-1, ret);
    }

    char filename[256];
    sprintf(filename, "bcrypt_midstate_%02d.dat", i);
    FILE *f = fopen(filename, "w");
    fwrite(&data, sizeof(data), 1, f);
    fclose(f);

    BF_crypt_clone(&clone, &data);
    BF_crypt_output(&clone, output, sizeof(output));
    BF_crypt_extkey(&data, kwk);
    output[4] = '0' + i / 10;
    output[5] = '0' + i % 10;

    sprintf(filename, "bcrypt_test_vector_%02d.txt", i);
    f = fopen(filename, "w");
    fprintf(f, "%s\n", output);
    fprintf(stderr, "%s\n", output);
    fclose(f);

    /*
    chachapoly_init(&ccp, kwk);
    chachapoly_wrap(&ccp, (uint8_t *)output, BF_HASH_LEN, key, (uint8_t *)wrapped);

    wrapped_b64[0] = '$';

    BF_betoh(wrapped, 12);
    BF_encode(wrapped_b64+1, (BF_word *)wrapped, 48);

    BF_decode((BF_word *)wrapped, wrapped_b64+1, 48);
    BF_htobe(wrapped, 12);

    int q = chachapoly_unwrap(&ccp, (uint8_t *)output, BF_HASH_LEN, (uint8_t *)wrapped, uwk);

    fprintf(stderr, "kwk: ");
    for (int i = 0; i < 32; ++i) fprintf(stderr, "%02x", kwk[i]);
    fprintf(stderr, "\n");

    if (q == 0) {
      fprintf(stderr, "key: ");
      for (int i = 0; i < 32; ++i) fprintf(stderr, "%02x", uwk[i]);
      fprintf(stderr, "\n");
    }

    fprintf(stderr, "%s%s %d\n", output, wrapped_b64, ret);
    */
  }

  return ret;
}

int bcrypt_check(const uint8_t *key, const char *input) {
  char *retval;
  int saved_errno;
  char output[BF_HASH_LEN + 1];
  struct BF_data data;
  magic(input, output, sizeof(output));
  retval = BF_crypt(&data, key, input, output, sizeof(output), 0);

  saved_errno = errno;
  if (BF_test(&data, 0) == 0) {
    errno = saved_errno;
    if (retval != NULL) {
      char v = 0;
      for (int i = 0; i < BF_HASH_LEN; ++i) v |= input[i] ^ output[i];
      if (v == 0) return 1;
    }
  }

  return 0;
}

char *bcrypt_ext_create(const uint8_t *key, uint8_t *ext, char *output, int size, int workfactor) {
  if (size < BF_EXT_LEN + 1) {
    errno = ERANGE;
    return NULL;
  }

  char *retval;
  int saved_errno;
  struct BF_data data;
  char setting[BF_SETTING_LEN + 1];
  if (BF_salt(setting, sizeof(setting), workfactor) == NULL) return NULL;
  magic(setting, output, size);

  retval = BF_crypt(&data, key, setting, output, size, 4);

  saved_errno = errno;
  if (BF_test(&data, 0) == 0) {
    errno = saved_errno;

    if (retval != NULL) {
      if (csprng(ext, 32) < 32) {
        errno = errno || EIO;
        return NULL;
      }

      uint8_t kwk[32];
      BF_word wrapped[12];
      struct chachapoly_ctx ccp;
      BF_crypt_extkey(&data, kwk);
      chachapoly_init(&ccp, kwk);
      chachapoly_wrap(&ccp, (uint8_t *)output, BF_HASH_LEN, ext, (uint8_t *)wrapped);
      BF_betoh(wrapped, 12);
      output[BF_HASH_LEN] = '$';
      BF_encode(output+BF_HASH_LEN+1, (BF_word *)wrapped, 48);
      output[BF_EXT_LEN] = '\0';
    }

    return retval;
  }

  magic(setting, output, size);
  errno = EINVAL;
  return NULL;
}

char *bcrypt_create(const uint8_t *key, char *output, int size, int workfactor) {
  char *retval;
  int saved_errno;
  struct BF_data data;
  char setting[BF_SETTING_LEN + 1];
  if (BF_salt(setting, sizeof(setting), workfactor) == NULL) return NULL;
  magic(setting, output, size);

  retval = BF_crypt(&data, key, setting, output, size, 4);

  saved_errno = errno;
  if (BF_test(&data, 0) == 0) {
    errno = saved_errno;
    return retval;
  }

  magic(setting, output, size);
  errno = EINVAL;
  return NULL;
}
