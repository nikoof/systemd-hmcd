#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "net.h"
#include "crypt.h"

#define NOB_IMPLEMENTATION
#include "../nob.h"

#define FLAG_IMPLEMENTATION
#include "flag.h"

void usage(FILE *stream) {
  fprintf(stream, "./systemd-hmcd [OPTIONS]\n");
  fprintf(stream, "OPTIONS:\n");
  flag_print_options(stream);
}

int main(int argc, char **argv) {
  bool *help = flag_bool("help", false, "Print this message and exit.");
  bool *listen = flag_bool("listen", false, "Listen or connect.");
  char **key_fpr = flag_str("recipient", NULL, "GPG fingerprint of recipient key.");
  uint64_t *port = flag_uint64("port", 6969, "Port to listen on.");

  if (!flag_parse(argc, argv)) {
    usage(stderr);
    flag_print_error(stderr);
    exit(EXIT_FAILURE);
  }

  if (*help) {
    usage(stdout);
    exit(EXIT_SUCCESS);
  }

  const char *in = "Hallo, Leute!\n";
  char out1[1024] = {0}, out2[1024] = {0};

  hmc_crypt_init();
  hmc_crypt_encrypt("FE9CEE73394A8F43A239F91394B9F744D3E82C46", in, strlen(in) - 1, out1, 1024);
  printf("%s\n", out1);

  hmc_crypt_decrypt(out1, strlen(out1) - 1, out2, 1024);
  printf("%s\n", out2);

  printf("listen: %d\n", *listen);
  printf("key_fpr: %s\n", *key_fpr);
  printf("port: %zu\n", *port);

  return 0;
}
