#include <assert.h>
#include <tomcrypt.h>
#include "PIUTools_SDK.h"
#include "pro1_data_zip.h"
#include "sha1.h"
#include "sig.h"

typedef ssize_t (*read_func_t)(int, void *, size_t);
typedef int (*lseek_func_t)(int, off_t, int);

static rsa_key our_rsa_key;
int key_imported = 0;
int sprng_idx, sha1_idx;

int generate_file_signature(zip_enc_context *ctx, int fd,
        read_func_t read_func, lseek_func_t lseek_func,
        uint8_t *out) {
    // get file size
    off_t fsize = lseek_func(fd, -133, SEEK_END);
    lseek_func(fd, 0, SEEK_SET);

    // get double SHA1 of header+data
    sha1nfo ctx, ctx2;
    size_t remaining = fsize, got;
    uint8_t buf[4096];
    uint8_t filehash[20];
    int err;

    ltc_mp = ltm_desc;
    if ((sprng_idx = register_prng(&sprng_desc)) == -1) {
        fprintf(stderr, "Could not register SPRNG\n");
        return -1;
    }
    if ((sha1_idx = register_hash(sha1_desc)) == -1) {
        fprintf(stderr, "Could not register SHA1 hash descriptor\n");
        return -1
    }

    sha1_init(&ctx);
    sha1_init(&ctx2);

    do  {
        got = read_func(fd, buf, min(4096, remaining));
        sha1_write(&ctx, buf, got);
        remaining -= got;
    } while (remaining > 0);
    sha1_write(&ctx2, sha1_result(&ctx), 20);
    memcpy(filehash, sha1_result(&ctx2), 20);

    if (key_imported == 0) {
        if ((err = rsa_import(our_privkey, sizeof(our_privkey), &our_rsa_key)) != CRYPT_OK) {
            fprintf(stderr, "Could not import RSA key: %s\n", error_to_string(err));
            return -1;
        }
        key_imported = 1;
    }

    int sigout = 128;

    if ((err = rsa_sign_hash_ex(filehash, 20, ctx->sig, &sigout, LTC_PKCS_1_V1_5, NULL, sprng_idx, sha1_idx, 0, &our_rsa_key)) != CRYPT_OK) {
        fprintf(stderr, "Could not sign hash: %s\n", error_to_string(err));
        return -1;
    }
    assert(sigout == 128);

    return 0;
}
