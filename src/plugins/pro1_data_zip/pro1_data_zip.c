/**
 * pro1_data_zip: add transparent encryption to prior decrypted data
 * zips for Pump Pro 1
 */
#include <stdint.h>
#include <string.h>
#include "plugin_sdk/plugin.h"
#include "plugin_sdk/dbg.h"
#include "plugin_sdk/enc_zip_file.h"
#include "plugin_sdk/dongle.h"
#include "aes.h"

#define min(x,y) ((x) > (y) ? (y) : (x))

typedef int (*open_func_t)(const char *, int);
open_func_t next_open;
typedef int (*close_func_t)(int);
close_func_t next_close;
typedef ssize_t (*read_func_t)(int, void *, size_t);
read_func_t next_read;
typedef int (*lseek_func_t)(int, off_t, int);
read_func_t next_lseek;

static char *data_zip_dir;

/**
 * bookkeeping for each opened file
 */
typedef struct zip_enc_context {
    char *pathname;
    int fd;
    off_t pos;
    uint8_t aes_key[24];
    AesContext aes_ctx;
    enc_zip_file_header *header;
    zip_enc_context *next;
    // each data zip has a signature file that is signed by the private
    // key linked to /Data/public.rsa (the validation of which is
    // exptected to be thwarted in another plugin)
    uint8_t sig[128];
} zip_enc_context;

static zip_enc_context *head = NULL, *tail = head;

// ugly routine yanked from sm-ac-tools
void saltHash(uint8_t *salted, const uint8_t salt[16], int addition) {
	int cSalt = 0, cSalt2 = 0, cSalt3 = 0;

	cSalt = (int)(salt[0]);
	cSalt2 = (int)(salt[1]);
	cSalt3 = (int)(salt[9]);
	cSalt += addition;
	salted[0] = (char)cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[2]);
	salted[1] = (char)cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[3]);
	salted[2] = (char)cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[4]);
	salted[3] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[5]);
	salted[4] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[6]);
	salted[5] = (char)cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[7]);
	salted[6] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[8]);
	salted[7] = (char)cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[10]);
	salted[8] = (char)cSalt2;
	cSalt2 >>= 8;
	cSalt3 += cSalt2;
	cSalt2 = (int)(salt[11]);
	salted[9] = (char)cSalt3;
	cSalt3 >>= 8;
	cSalt += cSalt3;
	salted[10] = cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[12]);
	salted[11] = cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[13]);
	salted[12] = cSalt;
	cSalt >>= 8;
	cSalt += cSalt2;
	cSalt2 = (int)(salt[14]);
	salted[13] = cSalt;
	cSalt >>= 8;
	cSalt2 += cSalt;
	cSalt = (int)(salt[15]);
	salted[14] = cSalt2;
	cSalt2 >>= 8;
	cSalt += cSalt2;
	salted[15] = cSalt;
}

static char *verify_block_plaintext = "<<abcdefghijklmn";

zip_enc_context *create_new_context(char *path, int fd) {
    AesContext aes_ctx;
    uint8_t salted[16];

    zip_enc_context *ctx = (zip_enc_context *)malloc(sizeof zip_enc_context);
    ctx->fd = fd;
    ctx->pos = 0;
    ctx->header = generate_header(fd);

    // derive key and verify block
    if (derive_aes_key_from_ds1963s(ctx->header, ctx->aes_key) != 0) {
        fprintf(stderr, "failed to derive AES key from ds1963s\n");
        return NULL;
    }
    saltHash(salted, header->salt, 0x123456);
    AesInitialise192(ctx->aes_key, &ctx->aes_ctx);
    AesEncrypt(&ctx->aes_ctx, salted, ctx->verify_block);
    for (int i = 0; i < 16; i++) {
        ctx->header->verify_block[i] ^= verify_block_plaintext[i];
    }

    if (head == NULL) {
        head = ctx;
        tail = head;
    } else {
        tail->next = ctx;
        tail = ctx;
    }
    return ctx;
}

zip_enc_context *find_context_by_fd(int fd) {
    zip_enc_context *stl = head;
    while (stl != NULL) {
        if (stl->fd == fd) {
            return stl;
        }
        stl = stl->next;
    }
    return NULL;
}

zip_enc_context *find_context_by_path(char *path) {
    zip_enc_context *stl = head;
    while (stl != NULL) {
        // XXX: normalize path (if even needed)?
        if (strncmp(path, stl->pathname, strlen(path)) == 0) {
            return stl;
        }
        stl = stl->next;
    }
    return NULL;
}

int is_data_zip_file(const char *path) {
    /* 1 = data zip, 0 = not */
    if (data_zip_dir == NULL) {
        return 0;
    }
    return (strstr(path, data_zip_dir) == path) ? 1 : 0;
}

/* determines if it's a data zip file and registers a context with it */
int pro1_data_zip_open(const char *path, int flags) {
    zip_enc_context *zip_ctx = find_context_by_path(path);
    int fd = next_open(path, flags);
    if (fd == -1) {
        perror("open()");
        return -1;
    }
    if (is_data_zip_file(path)) {
        if (zip_ctx == NULL) {
            DBG_printf("%s: opening new data zip file (%s)\n", __FUNCTION__, path);
            zip_ctx = create_new_context(path, fd);
        } else {
            DBG_printf("%s: opening prior opened data zip file (%s)\n", __FUNCTION__, path);
        }
        zip_ctx->pos = 0;
    }
    return fd;
}

ssize_t pro1_data_zip_read(int fd, void *buf, size_t count) {
    // fool the client into reading additional data before or after the
    // file itself such as the crypt header or file signature
    size_t remaining = count;
    off_t data_start = sizeof(enc_zip_file_header), sig_start;
    int got = 0;
    zip_enc_context *zip_ctx = find_context_by_fd(fd);
    if (remaining == 0 || zip_ctx == NULL) {
        return next_read(fd, buf, count);
    }
    sig_start = data_start + zip_ctx->header->file_size;

    if (zip_ctx->pos < data_start) {
        // read header first if applicable
        size_t header_count = min(remaining, data_start-zip_ctx->pos);
        memcpy(buf, (void *)zip_ctx->header, header_count);
        remaining -= header_count;
        zip_ctx->pos += header_count;
        got += header_count;
    }
    if (zip_ctx->pos < sig_start && remaining > 0) {
        uint8_t salt_copy[16], decbuf[4080];
        int num_crypts = 0, scoped_pos = 0;
        off_t cur_file_pos = zip_ctx->pos - data_start;

        // read encrypted data in 4080-byte blocks, as the key is
        // reset every 4080 bytes

        // how much data is left for us to read
        size_t encrypted_data_remaining = min(remaining, sig_start-zip_ctx->pos);
        // the position in the data section of our "container" file
        off_t encrypted_data_pos = zip_ctx->pos - data_start;
        uint8_t salt_copy[16], decbuf[4080], dsalted[16];
        size_t read_block_size = 4080 - (encrypted_data_pos % 4080);
        int crypt_operations_in_block = read_block_size / 16;
        if (read_block_size % 16 > 0) {
            crypt_operations_in_block++;
        }
        // prepare salt
        memcpy(salt_copy, zip_ctx->header->salt, sizeof salt_copy);
        *((__uint128_t *)salt_copy) += block_start;
        // encrypt contained data
        while (encrypted_data_remaining > 0) {
            int crypt_got = next_read(fd, decbuf, read_block_size);
            if (crypt_got == -1) {
                perror("read()");
                return -1;
            }
            int num_crypt_operations = crypt_got / 16;
            if (crypt_got % 16 > 0) {
                num_crypt_operations++;
            }
            for (int i = 0; i < num_crypt_operations; i++) {
                AesEncrypt(&zip_ctx->aes_ctx, salt_copy, dsalted);
                (*((__uint128_t *)salt_copy))++;
                for (int j = 0; j < 16; j++) {
                    buf[got] = dsalted[j] ^ decbuf[i*16+j];
                    got++;
                    remaining--;
                    encrypted_data_remaining--;
                    encrypted_data_pos++;
                    zip_ctx->pos++;
                }
            }
            read_block_size = 4080 - (encrypted_data_pos % 4080);
        }
    }
    if (zip_ctx->pos >= sig_start && remaining > 0) {
        // read signature
        size_t read_from_sig = min(remaining, sizeof(zip_ctx->sig));
        memcpy(buf+got, (void *)zip_ctx->sig, read_from_sig);
        zip_ctx->pos += read_from_sig;
        got += read_from_sig;
    }
    return got;
}

static HookEntry entries[] = {
    HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "open", pro1_data_zip_open, &next_open, 1),
    /*HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "close", pro1_data_zip_close, &next_close, 1),*/
    HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "read", pro1_data_zip_read, &next_read, 1),
    HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "lseek", pro1_data_zip_lseek, &next_lseek, 1),
    {}    
};

static int parse_config(void* user, const char* section, const char* name, const char* value){    
    if(strcmp(section,"PRO1_DATA_ZIP") == 0 && strcmp(name, "data_zip_dir") == 0){
        if(value == NULL){return 1;}
        data_zip_dir = value;
    }
    return 1;
}


const PHookEntry plugin_init(const char* config_path) {
}
