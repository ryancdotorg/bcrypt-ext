#pragma once

#include "bcrypt-ext.h"

int BF_decode(BF_word *dst, const char *src, int size);
void BF_encode(char *dst, const BF_word *src, int size);
