#pragma once

/* INCLUDES */
#include "../libft/include/libft.h"

/* CONSTANTS */
#define PATCH "code_injection"
#define DFLT_KEY_LEN 16
#define URANDOM "/dev/urandom"

/* ERRORS */
#define USAGE_ERR "usage: ./code_injection <path/to/binary> "
#define KEYGEN_ERR "could not generate key"
#define CORRUPT_ERR "file is corrupted"
#define FORMAT_ERR "file format is not supported"

#define HANDLER_ERR "read handler binary failed"
#define PARASITE_ERR "read parasite binary failed"
#define DECRYPTOR_ERR "read decryptor binary failed"


/* UTILS */
int write_error(const char *filename, const char *custmsg);
