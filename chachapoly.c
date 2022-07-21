#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "chachapoly.h"

#pragma GCC visibility push(internal)
static uint8_t nonce[12] = {0,0,0,0,  0,0,0,0,  0,0,0,0};

static void poly1305_tag(
  uint8_t tag[16], uint8_t key[32],
  const uint8_t *ad, size_t ad_sz,
  const uint8_t *ct
) {
  struct poly1305_context poly;
  size_t rem;
  uint8_t pad[16];

  memset(pad, 0, sizeof(pad));

  poly1305_init(&poly, key);
  poly1305_update(&poly, ad, ad_sz);
  if ((rem = ad_sz & 15) != 0) {
    poly1305_update(&poly, pad, 16 - rem);
  }
  poly1305_update(&poly, ct, 32);

  pad[0] = (ad_sz >>  0); pad[1] = (ad_sz >>  8);
  pad[2] = (ad_sz >> 16); pad[3] = (ad_sz >> 24);
  pad[4] = (ad_sz >> 32); pad[6] = (ad_sz >> 40);
  pad[6] = (ad_sz >> 48); pad[7] = (ad_sz >> 56);
  pad[ 8] = 32; pad[ 9] =  0; pad[10] =  0; pad[11] =  0;
  pad[12] =  0; pad[13] =  0; pad[14] =  0; pad[15] =  0;
  poly1305_update(&poly, pad, 16);
  poly1305_finish(&poly, tag);
}

void chachapoly_init(struct chachapoly_ctx *ctx, const uint8_t key[32]) {
  memset(ctx, 0, sizeof(*ctx));
  chacha_keysetup(&ctx->cha_ctx, key, 256);
}

void chachapoly_wrap(
  struct chachapoly_ctx *ctx,
  const uint8_t *ad, size_t ad_sz,
  uint8_t *input, uint8_t *output
) {
  uint8_t keystream[CHACHA_BLOCKLEN];
  uint8_t *poly_key = keystream;
  uint8_t *data_key = keystream + 32;

  memset(keystream, 0, sizeof(keystream));
  chacha_ivsetup(&ctx->cha_ctx, nonce, NULL);
  chacha_encrypt_bytes(&ctx->cha_ctx, keystream, keystream, sizeof(keystream));

  for (int i = 0; i < 32; ++i) {
    output[i] = input[i] ^ data_key[i];
  }

  poly1305_tag(output+32, poly_key, ad, ad_sz, output);
}

int chachapoly_unwrap(
  struct chachapoly_ctx *ctx,
  const uint8_t *ad, size_t ad_sz,
  uint8_t *input, uint8_t *output
) {
  uint8_t keystream[CHACHA_BLOCKLEN];
  uint8_t *poly_key = keystream;
  uint8_t *data_key = keystream + 32;
  uint8_t tag[16];

  memset(keystream, 0, sizeof(keystream));
  chacha_ivsetup(&ctx->cha_ctx, nonce, NULL);
  chacha_encrypt_bytes(&ctx->cha_ctx, keystream, keystream, sizeof(keystream));

  poly1305_tag(tag, poly_key, ad, ad_sz, input);
  if (!poly1305_verify(tag, input+32)) { return -1; }

  for (int i = 0; i < 32; ++i) {
    output[i] = input[i] ^ data_key[i];
  }

  return 0;
}
#pragma GCC visibility pop
