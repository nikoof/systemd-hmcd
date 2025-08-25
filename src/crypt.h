#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>
#include <gpgme.h>
#include "../nob.h"

// TODO: refactor later
extern gpgme_ctx_t hmc_crypt_ctx;

typedef struct {
    char *items;
    size_t count;
    size_t capacity;
    size_t rw_index;
} Hmc_String_Builder;

void hmc_crypt_init();
void hmc_crypt_encrypt(const char *recp, const char* in, size_t in_sz, Hmc_String_Builder *out);
void hmc_crypt_decrypt(const char *in, size_t in_sz, Hmc_String_Builder *out);

#endif
