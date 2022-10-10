#include "config.h"
#include "bcrypt-ext.h"
#include "memzero.h"
#include "codec.h"

#include <mariadb/mysql.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#define PASS_MAXLEN (71)

#define WORKFACTOR_MIN (4)
#define WORKFACTOR_MAX (16)
#define WORKFACTOR_DEFAULT (12)

#define WORKFACTOR_CLAMP(W) { \
if (W == -1) { W = WORKFACTOR_DEFAULT; } \
else if (W < WORKFACTOR_MIN) { W = WORKFACTOR_MIN; } \
else if (W > WORKFACTOR_MAX) { W = WORKFACTOR_MAX; } \
}

enum unwrap_format {FMT_BASE64, FMT_STRING, FMT_RAW};

/* copy mysql string to c string, adding null terminator, and returning error
 * if the mysql string contains any null bytes */
int my_str_to_c_str(char *dst, size_t dst_sz, char *src, size_t src_sz) {
  if ((src_sz + 1) > dst_sz || dst == NULL || src == NULL) return -1;

  size_t i;
  for (i = 0; i < src_sz; ++i) {
    if (src[i] == 0) { return -1; }
    dst[i] = src[i];
  }

  return dst[i] = 0;
}

my_bool bcrypt_hash_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count == 1) {
    args->arg_type[0] = STRING_RESULT;
  } else if (args->arg_count == 2) {
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = INT_RESULT;
  } else {
    strcpy(message, "need parameters: STRING [INTEGER]");
    return 1;
  }

  initid->max_length = (BF_HASH_LEN+1);
  initid->maybe_null = 1;
  initid->const_item = 0;
  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
char *bcrypt_hash(UDF_INIT *initid, UDF_ARGS *args, char *res, unsigned long *len, char *is_null, char *err) {
  /* password */
  char pass[PASS_MAXLEN+1];
  if (args->args[0] == NULL) {
    *is_null = 1;
    return 0;
  } else {
    if ((my_str_to_c_str(pass, sizeof(pass), args->args[0], args->lengths[0])) != 0) {
      *is_null = 1;
      return 0;
    }
  }

  /* work factor */
  long long workfactor;
  if (args->arg_count >= 2 && args->args[1] != NULL) {
    workfactor = *(long long*) args->args[1];
    WORKFACTOR_CLAMP(workfactor);
  } else {
    workfactor = WORKFACTOR_DEFAULT;
  }

  int saved_errno = errno;
  if (bcrypt_create((uint8_t *)pass, res, BF_HASH_LEN + 1, workfactor) == NULL) {
    *is_null = 1;
    res = NULL;
  } else {
    *len = BF_HASH_LEN;
  }
  errno = saved_errno;

  memzero(pass, sizeof(pass));

  return res;
}
#pragma GCC diagnostic pop

my_bool bcrypt_wrap_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count == 1) {
    args->arg_type[0] = STRING_RESULT;
  } else if (args->arg_count == 2) {
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = INT_RESULT;
  } else {
    strcpy(message, "need parameters: STRING [INTEGER]");
    return 1;
  }

  initid->max_length = (BF_EXT_LEN+1);
  initid->maybe_null = 1;
  initid->const_item = 0;
  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
char *bcrypt_wrap(UDF_INIT *initid, UDF_ARGS *args, char *res, unsigned long *len, char *is_null, char *err) {
  /* password */
  char pass[PASS_MAXLEN+1];
  if (args->args[0] == NULL) {
    *is_null = 1;
    return 0;
  } else {
    if ((my_str_to_c_str(pass, sizeof(pass), args->args[0], args->lengths[0])) != 0) {
      *is_null = 1;
      return 0;
    }
  }

  /* work factor */
  long long workfactor;
  if (args->arg_count >= 2 && args->args[1] != NULL) {
    workfactor = *(long long*) args->args[1];
    WORKFACTOR_CLAMP(workfactor);
  } else {
    workfactor = WORKFACTOR_DEFAULT;
  }

  int saved_errno = errno;
  uint8_t ext[32];
  if (bcrypt_ext_create((uint8_t *)pass, res, BF_EXT_LEN + 1, ext, workfactor) == NULL) {
    res = NULL;
    *is_null = 1;
  } else {
    *len = BF_EXT_LEN;
  }
  errno = saved_errno;

  memzero(pass, sizeof(pass));
  memzero(ext, sizeof(ext));

  return res;
}
#pragma GCC diagnostic pop

my_bool bcrypt_verify_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count != 2) {
    strcpy(message, "need parameters: STRING STRING");
    return 1;
  }

  args->arg_type[0] = STRING_RESULT;
  args->arg_type[1] = STRING_RESULT;
  initid->maybe_null = 1;
  initid->const_item = 0;
  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
long long bcrypt_verify(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *err) {
  /* password */
  char pass[PASS_MAXLEN+1];
  if (args->args[0] == NULL) {
    *is_null = 1;
    return 0;
  } else {
    if ((my_str_to_c_str(pass, sizeof(pass), args->args[0], args->lengths[0])) != 0) {
      memzero(pass, sizeof(pass));
      *is_null = 1;
      return 0;
    }
  }

  /* hash */
  char hash[BF_HASH_LEN+1];
  if (args->args[1] == NULL) {
    *is_null = 1;
    return 0;
  } else {
    if ((my_str_to_c_str(hash, sizeof(hash), args->args[1], args->lengths[1])) != 0) {
      *is_null = 1;
      return 0;
    }
  }

  int saved_errno = errno;
  int ret = bcrypt_check((uint8_t *)pass, hash);
  errno = saved_errno;

  memzero(pass, sizeof(pass));

  return ret;
}
#pragma GCC diagnostic pop

my_bool bcrypt_unwrap_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count == 2) {
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
  } else if (args->arg_count == 3) {
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
    args->arg_type[2] = STRING_RESULT;
  } else {
    strcpy(message, "need parameters: STRING STRING [STRING]");
    return 1;
  }

  initid->max_length = 45;
  initid->maybe_null = 1;
  initid->const_item = 0;
  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
char *bcrypt_unwrap(UDF_INIT *initid, UDF_ARGS *args, char *res, unsigned long *len, char *is_null, char *err) {
  /* password */
  char pass[PASS_MAXLEN+1];
  if (args->args[0] == NULL) {
    *is_null = 1;
    return NULL;
  } else {
    if ((my_str_to_c_str(pass, sizeof(pass), args->args[0], args->lengths[0])) != 0) {
      memzero(pass, sizeof(pass));
      *is_null = 1;
      return NULL;
    }
  }

  /* hash */
  char hash[BF_EXT_LEN+1];
  if (args->args[1] == NULL) {
    *is_null = 1;
    return NULL;
  } else {
    if ((my_str_to_c_str(hash, sizeof(hash), args->args[1], args->lengths[1])) != 0) {
      *is_null = 1;
      return NULL;
    }
  }

  /* format */
  int format = FMT_BASE64;
  if (args->arg_count >= 3 && args->args[2] != NULL) {
    if (strcasecmp(args->args[2], "base64") == 0) {
      format = FMT_BASE64;
    } else if (strcasecmp(args->args[2], "string") == 0) {
      format = FMT_STRING;
    } else if (strcasecmp(args->args[2], "raw") == 0) {
      format = FMT_RAW;
    } else {
      memzero(pass, sizeof(pass));
      *is_null = 1;
      return NULL;
    }
  }

  int saved_errno = errno;
  uint8_t ext[32];
  int ret = bcrypt_ext_check((uint8_t *)pass, hash, ext);
  errno = saved_errno;

  memzero(pass, sizeof(pass));

  if (ret == 0) {
    *is_null = 1;
    res = NULL;
  } else {
    switch (format) {
      case FMT_BASE64:
        b64_encode(res, 45, ext, 32);
        *len = 44;
        break;
      case FMT_STRING:
        b85_encode(res, 41, ext, 32);
        *len = 40;
        break;
      case FMT_RAW:
        memcpy(res, ext, 32);
        *len = 32;
        break;
      default:
        *is_null = 1;
        res = NULL;
    }
  }

  memzero(ext, 32);

  return res;
}
#pragma GCC diagnostic pop

my_bool bcrypt_rewrap_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  if (args->arg_count == 3) {
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
    args->arg_type[2] = STRING_RESULT;
  } else if (args->arg_count == 4) {
    args->arg_type[0] = STRING_RESULT;
    args->arg_type[1] = STRING_RESULT;
    args->arg_type[2] = STRING_RESULT;
    args->arg_type[3] = INT_RESULT;
  } else {
    strcpy(message, "need parameters: STRING STRING STRING [INTEGER]");
    return 1;
  }

  initid->max_length = (BF_EXT_LEN+1);
  initid->maybe_null = 1;
  initid->const_item = 0;
  return 0;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
char *bcrypt_rewrap(UDF_INIT *initid, UDF_ARGS *args, char *res, unsigned long *len, char *is_null, char *err) {
  /* old password */
  char old_pass[PASS_MAXLEN+1];
  if (args->args[0] == NULL) {
    *is_null = 1;
    return NULL;
  } else {
    if ((my_str_to_c_str(old_pass, sizeof(old_pass), args->args[0], args->lengths[0])) != 0) {
      memzero(old_pass, sizeof(old_pass));
      *is_null = 1;
      return NULL;
    }
  }

  /* new password */
  char new_pass[PASS_MAXLEN+1];
  if (args->args[1] == NULL) {
    *is_null = 1;
    return NULL;
  } else {
    if ((my_str_to_c_str(new_pass, sizeof(new_pass), args->args[1], args->lengths[1])) != 0) {
      memzero(old_pass, sizeof(old_pass));
      memzero(new_pass, sizeof(new_pass));
      *is_null = 1;
      return NULL;
    }
  }

  /* hash */
  char hash[BF_EXT_LEN+1];
  if (args->args[2] == NULL) {
    *is_null = 1;
    return NULL;
  } else {
    if ((my_str_to_c_str(hash, sizeof(hash), args->args[2], args->lengths[2])) != 0) {
      *is_null = 1;
      return NULL;
    }
  }

  /* work factor */
  long long workfactor;
  if (args->arg_count >= 4 && args->args[3] != NULL) {
    workfactor = *(long long*) args->args[3];
    WORKFACTOR_CLAMP(workfactor);
  } else {
    workfactor = -1;
  }

  int saved_errno = errno;
  errno = saved_errno;
  if (bcrypt_ext_rekey((uint8_t *)old_pass, (uint8_t *)new_pass, hash, BF_EXT_LEN + 1, workfactor) == NULL) {
    res = NULL;
    *is_null = 1;
  } else {
    memcpy(res, hash, BF_EXT_LEN);
    *len = BF_EXT_LEN;
  }
  errno = saved_errno;

  memzero(old_pass, sizeof(old_pass));
  memzero(new_pass, sizeof(new_pass));

  return res;
}
#pragma GCC diagnostic pop
