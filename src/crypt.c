#include "crypt.h"

#include <locale.h>
#include <assert.h>
#include <gpgme.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "util.h"

// TODO: refactor later
gpgme_ctx_t hmc_crypt_ctx;

ssize_t hmc_read_net(void *handle, void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  return read(e->net_fd, buffer, size);
}

ssize_t hmc_write_file(void *handle, const void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  return write(e->file_fd, buffer, size);
}

ssize_t hmc_read_file(void *handle, void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  return read(e->file_fd, buffer, size);
}

ssize_t hmc_write_net(void *handle, const void *buffer, size_t size) {
  Hmc_Data_Client *e = (Hmc_Data_Client*)handle;
  return send(e->net_fd, buffer, size, 0);
}

void hmc_crypt_init() {
  setlocale(LC_ALL, "");

  gpgme_check_version(NULL);
  GERR(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "Failed GPGME version check");
  GERR(gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL)), "Failed to set GPGME locale");

  GERR(gpgme_new(&hmc_crypt_ctx), "Failed to initialize GPGME context");
  gpgme_set_armor(hmc_crypt_ctx, 1);
}

void hmc_crypt_encrypt(const char *recp, const char* in, size_t in_sz, Hmc_String_Builder *out) {
  gpgme_key_t recp_key[2] = {0};
  GERR(gpgme_get_key(hmc_crypt_ctx, recp, &recp_key[0], 0), "Failed to get key with fingerprint %s", recp);

  gpgme_data_t data_in = {0}, data_out = {0};
  GERR(gpgme_data_new_from_mem(&data_in, in, in_sz, 1), "Failed to create GPGME data object");
  // GERR(gpgme_data_new_from_cbs(&data_out, &GPGME_DATA_SB, out), "Failed to create GPGME data object");

  GERR(gpgme_op_encrypt(hmc_crypt_ctx, recp_key, GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out), "Failed to encrypt data");
  gpgme_encrypt_result_t result = gpgme_op_encrypt_result(hmc_crypt_ctx);
  if (result->invalid_recipients) {
    nob_log(NOB_ERROR, "Invalid recipient(s) %s\n", result->invalid_recipients->fpr);
  }

  gpgme_data_release(data_in);
  assert(gpgme_data_seek(data_out, 0, SEEK_SET) == 0);
}

void hmc_crypt_decrypt(const char *in, size_t in_sz, Hmc_String_Builder *out) {
  gpgme_data_t data_in = {0}, data_out = {0};
  GERR(gpgme_data_new_from_mem(&data_in, in, in_sz, 1), "Failed to create GPGME data object");
  GERR(gpgme_data_new_from_cbs(&data_out, &GPGME_DATA_SB, out), "Failed to create GPGME data object");

  GERR(gpgme_op_decrypt(hmc_crypt_ctx, data_in, data_out), "Failed to decrypt data");

  assert(gpgme_data_seek(data_out, 0, SEEK_SET) == 0);
}
