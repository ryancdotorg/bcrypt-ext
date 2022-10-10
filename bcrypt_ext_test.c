#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bcrypt-ext.h"
#include "codec.h"

static char *hex(char *buf, size_t buf_sz, const uint8_t *in, size_t in_sz) {
  char *ret = buf;
  if (buf_sz < in_sz * 2 + 1) {
    return NULL;
  }
  for (size_t p = 0; p < in_sz; ++p) {
    buf += sprintf(buf, "%02x", in[p]);
  }
  buf[0] = '\0';
  return ret;
}


int main(int argc, char *argv[]) {
#define WORKFACTOR(POS, DEFAULT) (workfactor = (argn >= POS) ? atoi(argv[POS]) : DEFAULT)

  int workfactor = 4, ret = 0, argn = argc - 1;
  char hash[BF_EXT_LEN+1];
  char *output;
  uint8_t ext[32];

  char buf[513];

  if (argn == 0) {
    ret = bcrypt_test();
    printf("bcrypt self test returned %d\n", ret);

  } else if (argn == 1 && strcmp(argv[1], "bench") == 0) {
    double diff;
    int64_t lastns = 0;
    for (int i = 0; i <= 12; ++i) {
      int64_t ns = bcrypt_bench(i);
      double ms = (double)ns/1e6;
      printf("bench %02d: %7.3fms", i, ms);
      if (lastns > 0) {
        diff = (double)ns / (double)lastns;
        printf(" (%.3fx)", diff);
      }
      printf("\n");
      lastns = ns;
    }

  } else if (argn == 2 && strcmp(argv[1], "target") == 0) {
    int result = bcrypt_target(atoi(argv[2]));
    printf("%d\n", result);
    if (result < 0) ret = 1;

  } else if (argn >= 2 && argn <= 3 && strcmp(argv[1], "create") == 0) {
    WORKFACTOR(3, 12);
    output = bcrypt_create((uint8_t *)argv[2], hash, sizeof(hash), workfactor);
    ret = output == NULL ? 1 : 0;
    printf("%s\n", output);

  } else if (argn >= 2 && argn <= 3 && strcmp(argv[1], "ext_create") == 0) {
    WORKFACTOR(3, 12);
    output = bcrypt_ext_create((uint8_t *)argv[2], hash, sizeof(hash), ext, workfactor);
    b64_encode(buf, sizeof(buf), ext, sizeof(ext));
    printf("%s\n%s\n", output, buf);
    b85_encode(buf, sizeof(buf), ext, sizeof(ext));
    printf("%s\n", buf);

  } else if (argn == 3 && strcmp(argv[1], "check") == 0) {
    ret = bcrypt_check((uint8_t *)argv[3], argv[2]) == 1 ? 0 : 1;
    printf("%s\n", ret == 0 ? "okay" : "fail");

  } else if (argn == 3 && strcmp(argv[1], "ext_check") == 0) {
    ret = bcrypt_ext_check((uint8_t *)argv[3], argv[2], ext) == 1 ? 0 : 1;
    b64_encode(buf, sizeof(buf), ext, sizeof(ext));
    if (ret == 0) printf("%s\n", buf);
    b85_encode(buf, sizeof(buf), ext, sizeof(ext));
    if (ret == 0) printf("%s\n", buf);

  } else if (argn >= 4 && argn <= 5 && strcmp(argv[1], "ext_rekey") == 0) {
    WORKFACTOR(5, -1);
    strncpy(hash, argv[2], sizeof(hash)-1);
    output = bcrypt_ext_rekey((uint8_t *)argv[3], (uint8_t *)argv[4], hash, sizeof(hash), workfactor);
    ret = output == NULL ? 1 : 0;
    printf("%s\n", output);

  } else {
    fprintf(stderr, "Invalid arguments!\n");
    ret = 1;
  }
  return ret;
#undef WORKFACTOR
}
