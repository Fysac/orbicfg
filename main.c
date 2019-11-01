#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Definitions for uClibc's rand(3) implementation.
#include "uclibc/random.h"

// Configuration settings downloaded from the admin interface pretend to be a tar archive.
#define WEB_CONFIG_TAR_NAME "photos.tar"
// The real encrypted data is at this offset.
#define WEB_CONFIG_OFFSET 0xa0000

// Format: [magic (4 bytes), config length (4 bytes), crc (4 bytes)]
// Values are stored little-endian.
#define HEADER_SIZE 12

#define MAX_HEADER_AND_CONFIG_SIZE 0x39000

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <config backup (e.g. NETGEAR_Orbi.cfg)>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return EXIT_FAILURE;
    }

    unsigned char *buf = malloc(MAX_HEADER_AND_CONFIG_SIZE);
    if (!buf) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    memset(buf, 0, MAX_HEADER_AND_CONFIG_SIZE);

    fread(buf, strlen(WEB_CONFIG_TAR_NAME), 1, f);
    if (!strncmp((char *) buf, WEB_CONFIG_TAR_NAME, strlen(WEB_CONFIG_TAR_NAME))) {
        if (fseek(f, WEB_CONFIG_OFFSET, SEEK_SET) < 0) {
            perror("fseek");
            return EXIT_FAILURE;
        }
    } else {
        rewind(f);
    }

    fread(buf, MAX_HEADER_AND_CONFIG_SIZE, 1, f);
    fclose(f);

    uint32_t config_len = ((uint32_t *)buf)[1];
    assert(HEADER_SIZE + config_len <= MAX_HEADER_AND_CONFIG_SIZE);
    assert(config_len > 0 && config_len % sizeof(uint32_t) == 0);

    // Seed given to uClibc srand() to generate XOR keystream.
    // Often 0x20131224 or 0x23091293.
    uint32_t rand_magic = *((uint32_t *)buf);
    uclibc_srandom(rand_magic);

    // XOR every 4 bytes with the next call to uClibc rand().
    uint32_t *p = (uint32_t *)(buf + HEADER_SIZE);
    while (p < (uint32_t *)(buf + HEADER_SIZE + config_len)) {
        *p = *p ^ uclibc_random();
        p++;
    }

    int i = 0;
    for (i = HEADER_SIZE; i < config_len + HEADER_SIZE; i++) {
        if (buf[i] == '\0') {
            printf("\n");
        } else {
            printf("%c", buf[i]);
        }
    }

    free(buf);
    return EXIT_SUCCESS;
}
