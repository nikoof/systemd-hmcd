#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>
#include <gpgme.h>

// TODO: refactor later
extern gpgme_ctx_t hmc_crypt_ctx;

void hmc_crypt_init();
size_t hmc_crypt_encrypt(const char *recp, const char *in, size_t in_sz, char *out, size_t out_sz);
void hmc_crypt_decrypt(const char *in, size_t in_sz, char *out, size_t out_sz);

#endif
