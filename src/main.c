#include <stdio.h>
#include <locale.h>
#include <string.h>

#include "net.h"

#define NOB_IMPLEMENTATION
#include "../nob.h"

#include <gpgme.h>

#define ERR(cmd, fmt, args...) \
  { gpgme_error_t err; if ((err = cmd) != 0) { fprintf(stderr, fmt " (%s)\n", ##args, gpgme_strerror(err)); } }

int main(void) {
  setlocale(LC_ALL, "");

  gpgme_check_version(NULL);
  gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
  gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

  gpgme_ctx_t ctx;
  ERR(gpgme_new(&ctx), "init");
  gpgme_set_armor(ctx, 1);

  gpgme_data_t in = {0}, out = {0};
  ERR(gpgme_data_new_from_mem(&in, "Hallo, Leute!\n", 14, 0), "data from mem in");
  ERR(gpgme_data_new(&out), "create data out");

  gpgme_key_t key[2] = {NULL, NULL};
  ERR(gpgme_get_key(ctx, "FE9CEE73394A8F43A239F91394B9F744D3E82C46", &key[0], 0), "get key");

  ERR(gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out), "encrypt");
  gpgme_encrypt_result_t result = gpgme_op_encrypt_result(ctx);
  if (result->invalid_recipients) {
    fprintf(stderr, "Invalid recipient(s) %s\n", result->invalid_recipients->fpr);
  }

  char o[1024] = {0};
  gpgme_data_seek(out, 0, SEEK_SET);
  size_t cnt = gpgme_data_read(out, o, NOB_ARRAY_LEN(o));
  nob_log(NOB_INFO, "Read %zu bytes\n", cnt);
  for (size_t i = 0; i < cnt; ++i) {
    printf("%c", o[i]);
  }

  gpgme_data_release(in);
  gpgme_data_release(out);
}
