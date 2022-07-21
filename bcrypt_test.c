#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "bcrypt-ext.h"

int main(void) {
  int n = bcrypt_test();
  printf("return: %d\n", n);
  return n;
}
