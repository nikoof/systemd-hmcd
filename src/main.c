#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "net.h"
#include "util.h"
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

void print_progressbar(uint32_t cur, uint32_t tot) {
  uint32_t i;
  float proc = (float)cur / (float)tot;
  uint32_t width = 20;
  uint32_t donec = width * proc;
  /// TODO: Add colour
  fputc('[', stdout);
  for(i = 0; i < donec; ++i) { fputc('#', stdout); }
  for(i = donec; i < width; ++i) { fputc('-', stdout); }
  fprintf(stdout, "] (%3u%%)\r", (uint32_t)(proc * 100));
  fflush(stdout);
}

static struct gpgme_data_cbs SERVER_CBS = {
  .read = &hmc_read_net,
  .write = &hmc_write_file,
};

static struct gpgme_data_cbs CLIENT_CBS = {
  .read = &hmc_read_file,
  .write = &hmc_write_net,
};

void run_client(char **input, char **recipient, char **targetip, uint64_t *port) {
  if (*recipient == NULL || **recipient == '\0') {
    nob_log(NOB_ERROR, "Cannot connect to remote if encryption recipient is unknown!");
    usage(stderr); exit(EXIT_FAILURE);
  }

  if (*targetip == NULL || **targetip == '\0') {
    nob_log(NOB_ERROR, "Cannot connect to remote if target ip is unknown!");
    usage(stderr); exit(EXIT_FAILURE);
  }

  int32_t input_fd;
  struct hmc_net_socket_connect e;

  e.msglen = 2048;
  if (*input == NULL) {
    input_fd = STDIN_FILENO; e.datalen = 0;
  } else {
    ENEG((input_fd = open(*input, O_RDONLY)), "Could not open file %s! %m", *input);
    struct stat st; stat(*input, &st); e.datalen = st.st_size;
  }
  memset(&e.cipher_sb, 0, sizeof(e.cipher_sb));

  hmc_net_connect(&e, *targetip, *port);
  // hmc_net_send_handshake(&e, *recipient);

  char *input_buf;
  ENULL((input_buf = malloc(e.msglen)), "Could not allocate %u bytes for file reading!\n", e.msglen);

  Hmc_Data_Client dh = {
    .net_fd = e.fd,
    .file_fd = input_fd,
  };

  gpgme_data_t data_in = {0}, data_out = {0};
  GERR(gpgme_data_new_from_cbs(&data_in, &CLIENT_CBS, &dh), "Failed to create GPGME data object");
  GERR(gpgme_data_new_from_cbs(&data_out, &CLIENT_CBS, &dh), "Failed to create GPGME data object");

  gpgme_key_t recp_key[2] = {0};
  GERR(gpgme_get_key(hmc_crypt_ctx, *recipient, &recp_key[0], 0), "Failed to get key with fingerprint %s", *recipient);
  GERR(gpgme_op_encrypt(hmc_crypt_ctx, recp_key, GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out), "Failed to encrypt data");
}

void run_server(char **output, uint64_t *port) {
  int32_t output_fd;
  if (*output == NULL) { output_fd = STDOUT_FILENO; }
  else {
    ENEG(output_fd = open(*output, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH), "Could not open %s for writing! %m\n", *output);
  }
  struct hmc_net_socket_serve e;
  memset(&e.cipher_sb, 0, sizeof(e.cipher_sb));
  memset(&e.plaintext_sb, 0, sizeof(e.plaintext_sb));
  hmc_net_serve(&e, *port);

  Hmc_Data_Server dh = {
    .net_fd = e.remote_fd,
    .file_fd = output_fd,
  };

  gpgme_data_t data_in = {0}, data_out = {0};

  GERR(gpgme_data_new_from_cbs(&data_in, &SERVER_CBS, &dh), "Failed to create GPGME data object");
  GERR(gpgme_data_new_from_cbs(&data_out, &SERVER_CBS, &dh), "Failed to create GPGME data object");

  GERR(gpgme_op_decrypt(hmc_crypt_ctx, data_in, data_out), "Failed to decrypt data");
}

int main(int argc, char **argv) {
  bool *help = flag_bool("help", false, "Print this message and exit.");
  bool *listen = flag_bool("listen", false, "Listen or connect.");
  char **targetip = flag_str("targetip", NULL, "Peer ip to connect to.");
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

  // printf("listen: %d\n", *listen);
  // printf("key_fpr: %s\n", *recipient);
  // printf("port: %zu\n", *port);

  if (*listen) {
    run_server(output, port);
  } else {
    run_client(input, recipient, targetip, port);
  }

  return 0;
}
