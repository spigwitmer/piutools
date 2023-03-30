#include <stdint.h>
#include "enc_zip_file.h"
#include "plugin_sdk/crypt/sha1.h"
#include "ow/shaib.h"
#include "ow/ownet.h"
#include "plugin_sdk/dbg.h"

int derive_aes_key_from_ds1963s(const enc_zip_file_header *h, uint8_t out[24]) {
    uint8_t scratchpadWorkspace[60];

    sha1nfo key_seed, key_iter1, key_iter2;
    sha1_init(&key_seed);
    sha1_init(&key_iter1);
    sha1_init(&key_iter2);

    // sha1(subkey), sha1(subkey+sha1(subkey)), sha1(subkey+sha1(subkey+sha1(subkey)))
    sha1_write(&key_seed, h->subkey, 1024);
    memcpy(scratchpadWorkspace, sha1_result(&key_seed), 20);

    sha1_write(&key_iter1, h->subkey, 1024);
    sha1_write(&key_iter1, scratchpadWorkspace, 20);
    memcpy(scratchpadWorkspace+20, sha1_result(&key_iter1), 20);

    sha1_write(&key_iter2, h->subkey, 1024);
    sha1_write(&key_iter2, scratchpadWorkspace, 40);
    memcpy(scratchpadWorkspace+40, sha1_result(&key_iter2), 20);

    return ds1963s_compute_data_sha(scratchpadWorkspace, out);
}

int ds1963s_compute_data_sha(const uint8_t *input, uint8_t *out) {
    // XXX do ibutton shiz here
    return 0;
}
