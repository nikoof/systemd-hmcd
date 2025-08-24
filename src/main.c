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
  fprintf(stream, "usage: ./systemd-hmcd [OPTIONS]\n");
  fprintf(stream, "OPTIONS:\n");
  flag_print_options(stream);
}

int main(int argc, char **argv) {
  if (argc == 1) {
    hmc_net_serve(4040);
  } else {
    hmc_net_connect("127.0.0.1", 4040);
  }
  return 0;
  bool *help = flag_bool("help", false, "Print this message and exit.");
  bool *listen = flag_bool("listen", false, "Listen or connect.");
  char **recipient = flag_str("recipient", NULL, "GPG fingerprint of recipient key.");
  uint64_t *port = flag_uint64("port", 6969, "Port to listen on.");

  char **input = flag_str("input", NULL, "Input file. If unspecified, read from stdin.");
  char **output = flag_str("output", NULL, "Output file. If unspecified, print to stdout.");

  if (!flag_parse(argc, argv)) {
    usage(stderr);
    flag_print_error(stderr);
    exit(EXIT_FAILURE);
  }

  if (*help) {
    usage(stdout);
    exit(EXIT_SUCCESS);
  }

  if (!(*recipient) && !(*listen)) {
    usage(stderr);
    nob_log(NOB_ERROR, "Missing required parameter `-recipient`");
    exit(EXIT_FAILURE);
  }

  hmc_crypt_init();

  FILE *input_file  = (*input == NULL)  ? stdin  : fopen(*input, "r");
  FILE *output_file = (*output == NULL) ? stdout : fopen(*output, "w");

  Nob_String_Builder sb = {0};
  char out[1024] = {0};
  if (!(*listen)) {
    if (*input == NULL) {
      char buf[1 << 16] = {0};
      size_t count;
      while (!(count = fread(buf, 1, 1 << 16, input_file))) {
        nob_sb_append_buf(&sb, buf, count);
      }
      hmc_crypt_encrypt(*recipient, sb.items, sb.count, out, 1024);
      fprintf(output_file, "%s\n", out);
    } else {
      nob_log(NOB_INFO, "Reading from %s", *input);
      if (!nob_read_entire_file(*input, &sb)) exit(EXIT_FAILURE);
      hmc_crypt_encrypt(*recipient, sb.items, sb.count, out, 1024);
      fprintf(output_file, "%s\n", out);
    }
  } else {
    if (*input != NULL) {
      if (!nob_read_entire_file(*input, &sb)) exit(EXIT_FAILURE);
    }
    hmc_crypt_decrypt(sb.items, sb.count, out, 1024);
    fprintf(output_file, "%s\n", out);
  }


  printf("listen: %d\n", *listen);
  printf("key_fpr: %s\n", *recipient);
  printf("port: %zu\n", *port);

  return 0;
}
