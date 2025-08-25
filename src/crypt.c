#include "crypt.h"

#include <locale.h>
#include <assert.h>
#include <gpgme.h>

#include "util.h"

// TODO: refactor later
gpgme_ctx_t hmc_crypt_ctx;

ssize_t hmc_crypt_read_sb(void *handle, void *buffer, size_t size) {
  Hmc_String_Builder *sb = (Hmc_String_Builder*)handle;
  memcpy(buffer + sb->rw_index, sb->items, size);
  return size; // TODO: error reporting
}

ssize_t hmc_crypt_write_sb(void *handle, const void *buffer, size_t size) {
  Hmc_String_Builder *sb = (Hmc_String_Builder*)handle;
  nob_sb_append_buf(sb, buffer, size);
  return size; // TODO: error reporting
}

off_t hmc_crypt_seek_sb(void *handle, off_t offset, int whence) {
  Hmc_String_Builder *sb = (Hmc_String_Builder*)handle;
  switch (whence) {
  case SEEK_SET:
    sb->rw_index = offset;
    break;
  case SEEK_CUR:
    sb->rw_index += offset;
    break;
  case SEEK_END:
    sb->rw_index = sb->count - offset;
    break;
  default:
    return -1; // TODO: error reporting
  }

  return sb->rw_index;
}

void hmc_crypt_release_sb(void *handle) {
  nob_log(NOB_INFO, "Dis bih released they string builder!!!!!\n");
  nob_sb_free(*(Hmc_String_Builder*)handle);
}

struct gpgme_data_cbs GPGME_DATA_SB = {
  .read = &hmc_crypt_read_sb,
  .write = &hmc_crypt_write_sb,
  .seek = &hmc_crypt_seek_sb,
  .release = &hmc_crypt_release_sb,
};

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
  GERR(gpgme_data_new_from_cbs(&data_out, &GPGME_DATA_SB, out), "Failed to create GPGME data object");

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
