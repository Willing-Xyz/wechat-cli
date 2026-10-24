/* Synthetic objects only: never reads a user's WeChat process or keys. */
#ifndef SCANNER_SOURCE
#define SCANNER_SOURCE "../wechat_cli/bin/find_all_keys_macos.c"
#endif
#define main scanner_main
#include SCANNER_SOURCE
#undef main
#include <assert.h>

static void put_pointer(unsigned char *buf, size_t offset, uint64_t value) {
    memcpy(buf + offset, &value, sizeof(value));
}

int main(void) {
    /* A valid 64-digit key must not be rejected for using < 15 distinct digits. */
    const char *key = "0123456789abcd0123456789abcd0123456789abcd0123456789abcd01234567";
    const char *salt = "102132435465768798a9bacbdcedfe0f";
    char plain[100];
    snprintf(plain, sizeof(plain), "x'%s%s'", key, salt);
    unsigned char blob[99];
    for (size_t i = 0; i < sizeof(blob); i++)
        blob[i] = plain[i] ^ CONFIG_XOR_MASK[i % CONFIG_XOR_MASK_LEN];
    strcpy(g_db_salts[0], salt);
    strcpy(g_db_names[0], "synthetic.db");
    g_db_count = 1;

    /* Exercise both observed 4.1.13 copies and the older PR layout. */
    const size_t layouts[] = {0x68, 0x90, 0x88};
    for (size_t k = 0; k < sizeof(layouts) / sizeof(layouts[0]); k++) {
        unsigned char config[0xc0] = {0}, node[0x50] = {0};
        put_pointer(config, layouts[k] + 8, (uint64_t)blob);
        put_pointer(config, layouts[k] + 16, sizeof(blob));
        put_pointer(node, 0x10, (uint64_t)CONFIG_CIPHER_NAME);
        put_pointer(node, 0x18, CONFIG_CIPHER_NAME_LEN);
        put_pointer(node, 0x28, (uint64_t)config);
        key_entry_t keys[MAX_KEYS];
        uint64_t seen[MAX_CONFIG_POINTERS];
        int key_count = 0, seen_count = 0, candidates = 0;
        process_config_reference(mach_task_self(), (uint64_t)(node + 0x10),
            (uint64_t)CONFIG_CIPHER_NAME, keys, &key_count, seen, &seen_count, &candidates);
        if (key_count != 1) {
            fprintf(stderr, "FAIL: layout 0x%zx recovered %d keys, expected 1\n", layouts[k], key_count);
            return 1;
        }
        assert(strcmp(keys[0].key_hex, key) == 0);
        assert(strcmp(keys[0].salt_hex, salt) == 0);
    }
    puts("PASS: synthetic Config.Cipher layouts 0x68, 0x90, 0x88");
    return 0;
}
