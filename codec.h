#pragma once

#include <stdlib.h>
#include <stdint.h>

#include "bcrypt-ext.h"

int BF_decode(BF_word *dst, const char *src, int size);
void BF_encode(char *dst, const BF_word *src, int size);

ssize_t b64_decode(void *dst, const char *src, size_t size);
ssize_t b64_encode(char *dst, size_t dst_sz, const void *src, size_t src_sz);

ssize_t b85_encode(char *dst, size_t dst_sz, const void *src, size_t src_sz);
