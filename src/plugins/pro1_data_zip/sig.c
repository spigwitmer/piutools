#include <tomcrypt.h>
#include "pro1_data_zip.h"
#include "sig.h"

typedef ssize_t (*read_func_t)(int, void *, size_t);
typedef int (*lseek_func_t)(int, off_t, int);

void generate_file_signature(zip_enc_context *ctx, int fd,
                             read_func_t read_func, lseek_func_t lseek_func,
                             uint8_t *out) {
    // get file size
    off_t fsize = lseek_func(fd, -133, SEEK_END);
    lseek_func(fd, 0, SEEK_SET);

    // get double SHA1 of header+data

    // rsa_import our RSA privkey
    // rsa_sign_hash_ex or whatever
}
