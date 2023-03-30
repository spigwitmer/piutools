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

zip_enc_context *create_new_context(char *path, int fd) {
    zip_enc_context *ctx = (zip_enc_context *)malloc(sizeof zip_enc_context);
    ctx->fd = fd;
    ctx->pos = 0;
    ctx->header = generate_header(fd);
    if (derive_aes_key_from_ds1963s(ctx->header, ctx->aes_key) != 0) {
        fprintf(stderr, "failed to derive AES key from ds1963s\n");
        return NULL;
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
    if (data_zip_dir == NULL) {
        return 0;
    }
    return (strstr(path, data_zip_dir) == path) ? 1 : 0;
}

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
        // read encrypted data
        size_t encrypted_data_count = min(remaining, sig_start-zip_ctx->pos);
        int block_start = (zip_ctx->pos - data_start) / PRO1_AES_BLOCK_SIZE,
            block_count = remaining / PRO1_AES_BLOCK_SIZE;
        uint8_t *encbuf[PRO1_AES_BLOCK_SIZE];
        if (remaining % PRO1_AES_BLOCK_SIZE > 0)
            block_count++;
        off_t data_pos_start = block_start * PRO1_AES_BLOCK_SIZE;

        // derive key based on the position
        
        // XXX crypt stuff
        remaining -= encrypted_data_count;
        zip_ctx->pos += encrypted_data_count;
        got += encrypted_data_count;
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
