#pragma once

#include "chacha.h"
#include "poly1305-donna/poly1305-donna.h"

struct chachapoly_ctx {
  struct chacha_ctx cha_ctx;
};

void chachapoly_init(struct chachapoly_ctx *ctx, const uint8_t key[32]);

void chachapoly_wrap(
  struct chachapoly_ctx *ctx,
  const uint8_t *ad, size_t ad_sz,
  const uint8_t *input, uint8_t *output
);

int chachapoly_unwrap(
  struct chachapoly_ctx *ctx,
  const uint8_t *ad, size_t ad_sz,
  const uint8_t *input, uint8_t *output
);
