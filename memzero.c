#include "memzero.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#pragma GCC visibility push(internal)
// adapted from libsodium
#if !defined(_WIN32) && !defined(HAS_EXPLICIT_BZERO) && !defined(HAS_MEMSET_EXPLICIT) && defined(HAS_WEAK_SYMBOLS)
__attribute__((weak)) void
__dummy_symbol_to_prevent_memzero_lto(void *pnt, size_t len)
{
    (void) pnt;
    (void) len;
}
#endif

void memzero(void *p, size_t c) {
#if defined(_WIN32)
  SecureZeroMemory(pnt, len);
#elif defined(HAS_EXPLICIT_BZERO)
  explicit_bzero(p, c);
#elif defined(HAS_MEMSET_EXPLICIT)
  memset_explicit(p, 0, c);
#elif defined(HAS_WEAK_SYMBOLS)
  memset(p, 0, c);
  __dummy_symbol_to_prevent_memzero_lto(p, c);
#else
  volatile unsigned char *volatile ptr = (volatile unsigned char *volatile)p;
  size_t i = (size_t)0U;
  while (i < c) ptr[i++] = 0U;
#endif
}

#pragma GCC visibility pop
