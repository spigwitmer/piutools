#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include "tommath.h"
#define LTM_DESC
#include "tomcrypt.h"
#include "PIUTools_SDK.h"
#include "pro1_data_zip.h"
#include "sig.h"
#include "util.h"

//#define SIG_DEBUG
#undef SIG_DEBUG

static rsa_key our_rsa_key;
static int key_imported = 0;
static int sprng_idx, sha1_idx;

// the pubkey stored in the PIU Pro binary
const unsigned char their_pubkey[140] = {
	0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb7, 0x0d, 0x2c,
	0xe1, 0xf3, 0xaf, 0x2b, 0xec, 0xfb, 0xe3, 0x00, 0x75, 0x42,
	0xbf, 0x9b, 0xf5, 0x85, 0x9f, 0xf0, 0x8f, 0x2c, 0x36, 0x2a,
	0xb6, 0x7c, 0x81, 0x78, 0x3d, 0x05, 0x7f, 0xc6, 0xec, 0xd3,
	0x34, 0xed, 0x31, 0x73, 0x0b, 0xa4, 0x81, 0x25, 0xa8, 0xe2,
	0x0f, 0x02, 0xce, 0xba, 0x82, 0x95, 0xb9, 0x5a, 0x49, 0xc7,
	0xe6, 0x6e, 0xb3, 0xe2, 0xcc, 0xae, 0x18, 0x7f, 0x0f, 0xde,
	0x5f, 0x03, 0x06, 0x00, 0x3d, 0xa5, 0x15, 0x6d, 0x7e, 0x0e,
	0x8a, 0x8b, 0xbf, 0x26, 0x26, 0xee, 0x2a, 0xd8, 0x45, 0xdc,
	0xd2, 0xba, 0xf0, 0x44, 0x13, 0x6e, 0xc6, 0xc3, 0x79, 0x57,
	0xfc, 0x14, 0x32, 0x01, 0x95, 0x66, 0xe5, 0x34, 0x9c, 0xc6,
	0x49, 0xf3, 0xb0, 0x81, 0x6e, 0x26, 0x64, 0xa9, 0x9d, 0x04,
	0xa2, 0x44, 0x3a, 0xde, 0x3b, 0x5e, 0xa4, 0x6e, 0xfd, 0x28,
	0x01, 0xd2, 0xd9, 0x61, 0x45, 0x02, 0x03, 0x01, 0x00, 0x01,
};

// our replacement pub/privkeys
const unsigned char our_pubkey[140] = {
	0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xbb, 0xed, 0xa6, 0x26, 0xec, 0xe7, 0xc3, 0x60, 0x07,
	0xe7, 0xab, 0xf4, 0x05, 0x2f, 0xde, 0x6b, 0x86, 0x92, 0x65, 0x57, 0xf8, 0x57, 0xf5, 0xb2, 0x8f,
	0xe1, 0x2b, 0x4f, 0x73, 0xb1, 0x4a, 0xf1, 0xf2, 0xcc, 0x7f, 0x49, 0xd1, 0xd2, 0x48, 0xf1, 0x29,
	0x73, 0x59, 0x5c, 0x5d, 0x4a, 0x4f, 0x0f, 0x29, 0x15, 0xa8, 0xea, 0x7c, 0x92, 0x59, 0xa9, 0x8a,
	0x64, 0x5f, 0xba, 0x5a, 0x40, 0x43, 0x1f, 0x2d, 0x63, 0x5a, 0xd9, 0x31, 0x60, 0xd5, 0xa2, 0xac,
	0x99, 0xa1, 0xc9, 0x40, 0xf8, 0x92, 0xe5, 0x12, 0xe7, 0xa4, 0xeb, 0xe6, 0x02, 0xb3, 0xef, 0x5c,
	0xa4, 0x7f, 0x8f, 0x7f, 0xc8, 0x6f, 0xbe, 0x48, 0xaf, 0x0b, 0x67, 0x87, 0xd6, 0x73, 0xd3, 0xe8,
	0xba, 0x1f, 0x01, 0xfe, 0x9f, 0x35, 0xfd, 0xc1, 0x38, 0x7d, 0x39, 0x10, 0xed, 0x07, 0x77, 0x02,
	0xca, 0xf3, 0x52, 0xec, 0x7b, 0x1c, 0x83, 0x02, 0x03, 0x01, 0x00, 0x01
};

const unsigned char our_privkey[608] = {
	0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xbb, 0xed, 0xa6, 0x26, 0xec,
	0xe7, 0xc3, 0x60, 0x07, 0xe7, 0xab, 0xf4, 0x05, 0x2f, 0xde, 0x6b, 0x86, 0x92, 0x65, 0x57, 0xf8,
	0x57, 0xf5, 0xb2, 0x8f, 0xe1, 0x2b, 0x4f, 0x73, 0xb1, 0x4a, 0xf1, 0xf2, 0xcc, 0x7f, 0x49, 0xd1,
	0xd2, 0x48, 0xf1, 0x29, 0x73, 0x59, 0x5c, 0x5d, 0x4a, 0x4f, 0x0f, 0x29, 0x15, 0xa8, 0xea, 0x7c,
	0x92, 0x59, 0xa9, 0x8a, 0x64, 0x5f, 0xba, 0x5a, 0x40, 0x43, 0x1f, 0x2d, 0x63, 0x5a, 0xd9, 0x31,
	0x60, 0xd5, 0xa2, 0xac, 0x99, 0xa1, 0xc9, 0x40, 0xf8, 0x92, 0xe5, 0x12, 0xe7, 0xa4, 0xeb, 0xe6,
	0x02, 0xb3, 0xef, 0x5c, 0xa4, 0x7f, 0x8f, 0x7f, 0xc8, 0x6f, 0xbe, 0x48, 0xaf, 0x0b, 0x67, 0x87,
	0xd6, 0x73, 0xd3, 0xe8, 0xba, 0x1f, 0x01, 0xfe, 0x9f, 0x35, 0xfd, 0xc1, 0x38, 0x7d, 0x39, 0x10,
	0xed, 0x07, 0x77, 0x02, 0xca, 0xf3, 0x52, 0xec, 0x7b, 0x1c, 0x83, 0x02, 0x03, 0x01, 0x00, 0x01,
	0x02, 0x81, 0x80, 0x35, 0x7a, 0x4b, 0xa9, 0x51, 0x0a, 0x24, 0xd1, 0x5b, 0x7e, 0x84, 0x32, 0xb5,
	0x15, 0x29, 0xa4, 0x8c, 0x8f, 0x75, 0x52, 0x62, 0xc3, 0xd9, 0x11, 0x9e, 0x9a, 0xf3, 0x61, 0xb1,
	0x28, 0xf7, 0x0c, 0x41, 0xcd, 0x0a, 0xbd, 0xdd, 0x7d, 0x0b, 0x2f, 0xc1, 0x5d, 0x67, 0x44, 0xfe,
	0xf1, 0x29, 0xed, 0x45, 0x02, 0x3a, 0x66, 0xbb, 0xdb, 0x43, 0xb3, 0x98, 0xc3, 0xb6, 0x70, 0x07,
	0xc5, 0xb8, 0xb3, 0x95, 0x20, 0x6c, 0x7c, 0xad, 0x75, 0x02, 0x00, 0xa9, 0x1a, 0xea, 0xc6, 0xe0,
	0xc0, 0x7f, 0x0e, 0xc1, 0x12, 0x05, 0xe7, 0xf1, 0x32, 0x0d, 0x5a, 0x1a, 0xa3, 0xa5, 0xec, 0xe5,
	0x80, 0x0c, 0x04, 0x3e, 0x7f, 0xfb, 0x0b, 0x49, 0xbe, 0x67, 0xef, 0x8a, 0x5e, 0x98, 0x7e, 0xa1,
	0xb4, 0x4f, 0x57, 0x3d, 0x1b, 0xe3, 0xe9, 0x33, 0x3f, 0x91, 0x0c, 0x14, 0x83, 0xbc, 0xf1, 0x8c,
	0x47, 0xbc, 0xa1, 0x02, 0x41, 0x00, 0xfa, 0x53, 0xe3, 0x8e, 0x78, 0x1d, 0xae, 0x89, 0x03, 0x9c,
	0x0e, 0x9b, 0xd4, 0x70, 0xa4, 0x8c, 0x01, 0x9c, 0x90, 0x66, 0x1c, 0xa7, 0xf4, 0x86, 0x3f, 0x57,
	0x1f, 0xc5, 0xc3, 0x83, 0xe9, 0x82, 0x62, 0xbd, 0x7f, 0xdf, 0xd4, 0xbf, 0x56, 0x1f, 0xfe, 0xa4,
	0x5a, 0x88, 0x68, 0x47, 0xbe, 0xd5, 0xe1, 0x21, 0xb3, 0xf7, 0xfb, 0x7f, 0xac, 0xe6, 0x9d, 0x7f,
	0x9b, 0x6d, 0xb9, 0x16, 0x2b, 0xe3, 0x02, 0x41, 0x00, 0xc0, 0x2f, 0xca, 0x92, 0x58, 0x37, 0xa6,
	0x6f, 0x83, 0x7b, 0x0d, 0xe0, 0xd3, 0xd0, 0x60, 0x9e, 0xfa, 0x19, 0x0d, 0x82, 0x35, 0x93, 0xd8,
	0x18, 0xa7, 0x80, 0x55, 0x9d, 0xa3, 0x84, 0xd2, 0x2a, 0xd0, 0x9a, 0x1a, 0xa1, 0x21, 0xaf, 0x72,
	0xac, 0x4f, 0xf6, 0xdb, 0x39, 0x64, 0x01, 0x81, 0xc5, 0xda, 0x28, 0x3f, 0x1a, 0xf9, 0xc1, 0xc5,
	0x2c, 0x0d, 0x16, 0x72, 0x80, 0x41, 0xc1, 0x6e, 0xe1, 0x02, 0x40, 0x49, 0x29, 0x4f, 0x6e, 0x8a,
	0x28, 0x92, 0xa4, 0x34, 0xcb, 0xdd, 0x71, 0x29, 0xcb, 0xaa, 0x2b, 0xc9, 0x24, 0xcb, 0x07, 0x2d,
	0x04, 0xe1, 0x70, 0x82, 0xfe, 0xa1, 0xa8, 0x99, 0x15, 0xea, 0x9f, 0x52, 0xe0, 0x73, 0x89, 0x25,
	0x92, 0xae, 0x47, 0x37, 0x93, 0x2d, 0x6a, 0x84, 0x9f, 0xc3, 0x64, 0x9b, 0x21, 0xd0, 0x89, 0x7f,
	0x95, 0xb7, 0x20, 0xc7, 0x93, 0x4e, 0x07, 0xe9, 0x7a, 0x53, 0x65, 0x02, 0x40, 0x6c, 0x89, 0x91,
	0x09, 0xdd, 0x30, 0x70, 0x9a, 0x81, 0xd2, 0xb9, 0x1f, 0xc3, 0xff, 0xe6, 0xd1, 0x61, 0xc5, 0x4c,
	0x4f, 0xc1, 0x1a, 0x61, 0xec, 0x6a, 0x8c, 0x9b, 0xcd, 0x8f, 0x4f, 0xaf, 0xb1, 0xe6, 0x65, 0x61,
	0xac, 0xa6, 0x6d, 0x83, 0x81, 0xb5, 0x17, 0x60, 0xef, 0xa4, 0x7f, 0x05, 0x5f, 0x4b, 0xb9, 0x77,
	0x0a, 0x31, 0x0b, 0x31, 0xe3, 0x92, 0xf0, 0x9e, 0x71, 0xb8, 0xb1, 0x19, 0x81, 0x02, 0x41, 0x00,
	0xad, 0x4f, 0x5f, 0x26, 0x06, 0x26, 0x3f, 0xdb, 0x17, 0x2d, 0xd4, 0x0a, 0xcd, 0xa0, 0x76, 0x9a,
	0xef, 0x84, 0x1b, 0x59, 0xf8, 0x7d, 0x3f, 0x6f, 0x5d, 0xbf, 0x76, 0x42, 0xff, 0xe8, 0x71, 0x45,
	0xcb, 0x6e, 0xb7, 0xbe, 0x87, 0x72, 0xd4, 0x2a, 0xbb, 0x9e, 0xd2, 0xc6, 0x61, 0xc4, 0xce, 0xfb,
	0xb4, 0xa9, 0x3c, 0x75, 0xac, 0xa3, 0x89, 0xdf, 0x34, 0x98, 0xa9, 0x29, 0x6b, 0x79, 0xca, 0xcb
};


int generate_file_signature(zip_enc_context *ctx, int fd,
        read_func_t read_func, lseek_func_t lseek_func,
        uint8_t *out) {
    // get file size (sans sig and footer)
    off_t amt = lseek_func(fd, 0, SEEK_END) - 133;
    DBG_printf("[sig] File size: %lu\n", amt);
    lseek_func(fd, 0, SEEK_SET);

    // get double SHA1 of header+data
    hash_state shactx, shactx2;
    size_t got = 0, readsize = 0;
    uint8_t buf[0x10000];
    uint8_t filehash[20], sha1result[20];
    int err;
    off_t pos = 0;

    ltc_mp = ltm_desc;
    if ((sprng_idx = register_prng(&sprng_desc)) == -1) {
        fprintf(stderr, "Could not register SPRNG\n");
        return -1;
    }
    if ((sha1_idx = register_hash(&sha1_desc)) == -1) {
        fprintf(stderr, "Could not register SHA1 hash descriptor\n");
        return -1;
    }

    sha1_init(&shactx);
    sha1_init(&shactx2);
    long curpos = 0;

    while (pos < amt) {
        curpos = lseek_func(fd, pos, SEEK_SET);
        readsize = (amt < 0x10000) ? amt : 0x10000; 
        got = read_func(fd, buf, readsize);
        if (got != readsize) {
            fprintf(stderr, "%s: read_func(zip_fd) failed, got %d\n", __FUNCTION__, got);
            return -1;
        }
        sha1_process(&shactx, buf, got);
        DBG_printf("[pro1_data_zip:%s](%s) processed %d bytes at %lu(%lu)\n", __FUNCTION__, ctx->pathname, got, curpos, pos);
        if (pos + got >= amt) {
            break;
        }
        pos += 0x1000000;
        if (pos + 0x10000 > amt) {
            pos = amt - 0x10000;
        }
    }

    if ((err = sha1_done(&shactx, sha1result)) != CRYPT_OK) {
        fprintf(stderr, "sha1_done failed: %s\n", error_to_string(err));
        return -1;
    }
    sha1_process(&shactx2, sha1result, 20);
    if ((err = sha1_done(&shactx2, filehash)) != CRYPT_OK) {
        fprintf(stderr, "sha1_done failed: %s\n", error_to_string(err));
        return -1;
    }

    DBG_printf("%s hash1: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            ctx->pathname,
            sha1result[0], sha1result[1], sha1result[2], sha1result[3], sha1result[4], sha1result[5],
            sha1result[6], sha1result[7], sha1result[8], sha1result[9], sha1result[10], sha1result[11],
            sha1result[12], sha1result[13], sha1result[14], sha1result[15], sha1result[16], sha1result[17],
            sha1result[18], sha1result[19]);
    DBG_printf("%s hash2: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            ctx->pathname,
            filehash[0], filehash[1], filehash[2], filehash[3], filehash[4], filehash[5],
            filehash[6], filehash[7], filehash[8], filehash[9], filehash[10], filehash[11],
            filehash[12], filehash[13], filehash[14], filehash[15], filehash[16], filehash[17],
            filehash[18], filehash[19]);

    if (key_imported == 0) {
        if ((err = rsa_import(our_privkey, sizeof(our_privkey), &our_rsa_key)) != CRYPT_OK) {
            fprintf(stderr, "Could not import RSA key: %s\n", error_to_string(err));
            return -1;
        }
        key_imported = 1;
    }

    unsigned long sigout = 133;

    if ((err = rsa_sign_hash_ex(filehash, 20, ctx->sig, &sigout, LTC_PKCS_1_V1_5, NULL, sprng_idx, sha1_idx, 0, &our_rsa_key)) != CRYPT_OK) {
        fprintf(stderr, "Could not sign hash: %s\n", error_to_string(err));
        return -1;
    }
    assert(sigout == 128);

#ifdef SIG_DEBUG
    char sig_outfile[64];
    sprintf(sig_outfile, "%s.sig", basename(ctx->pathname));
    FILE *sfd = fopen(sig_outfile, "wb");
    if (sfd == NULL) {
        fprintf(stderr, "SIG_DEBUG: fopen(): %s\n", strerror(errno));
    } else {
        fwrite(ctx->sig, 1, sigout, sfd);
        fclose(sfd);
    }
#endif

    return 0;
}
