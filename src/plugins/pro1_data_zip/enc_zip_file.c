#include <errno.h>
#include <string.h>
#include "plugin/dbg.h"
#include "enc_zip_file.h"

void generate_random_bytes(uint8_t *buf, int count) {
    for (i = 0; i < count; i++) {
        buf[i] = rand() % 255;
    }
}


enc_zip_file_header *generate_header(int fd) {
    enc_zip_file_header *header = (enc_zip_file_header *)malloc(sizeof enc_zip_file_header);
    if (header == NULL) {
        perror("malloc()");
        return NULL;
    }

    strncpy(header->magic, ">>", 2);
    header->subkey_size = PRO1_SUBKEY_SIZE;
    generate_random_bytes(header->subkey, PRO1_SUBKEY_SIZE);
    generate_random_bytes(header->salt, PRO1_AES_BLOCK_SIZE);

    // get file size
    off_t curpos, fsize;
    curpos = lseek(fd, SEEK_CUR, 0);
    header->file_size = lseek(fd, SEEK_END, 0);
    lseek(fd, SEEK_SET, curpos);

    return header;
}
