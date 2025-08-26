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


typedef struct {
  int32_t net_fd;
  int32_t file_fd;
} Hmc_Data_Server;

typedef struct {
  int32_t net_fd;
  int32_t file_fd;
} Hmc_Data_Client;


void hmc_crypt_init();
void hmc_crypt_encrypt(const char *recp, const char* in, size_t in_sz, Hmc_String_Builder *out);
void hmc_crypt_decrypt(const char *in, size_t in_sz, Hmc_String_Builder *out);


ssize_t hmc_read_net(void *handle, void *buffer, size_t size);
ssize_t hmc_write_file(void *handle, const void *buffer, size_t size);
ssize_t hmc_read_file(void *handle, void *buffer, size_t size);
ssize_t hmc_write_net(void *handle, const void *buffer, size_t size);

#endif
