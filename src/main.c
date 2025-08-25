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
  int32_t i;
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
    ENEG((input_fd = open(*input, O_RDONLY)), "Could not open file %s! %m");
    struct stat st; stat(*input, &st); e.datalen = st.st_size;
  }

  hmc_net_connect(&e, *targetip, *port);
  hmc_net_send_handshake(&e, *recipient);

  char *input_buf;
  ENULL((input_buf = malloc(e.msglen)), "Could not allocate %u bytes for file reading!\n", e.msglen);

  ssize_t readl;
  while ((readl = read(input_fd, input_buf, e.msglen)) > 0) {
    hmc_net_send(&e, input_buf, readl);
  }
  ENEG(readl, "Could not read from %s! %m\n", (*input == NULL) ? "stdin" : *input)

  free(input_buf);

  hmc_net_close_connect(&e);
  close(input_fd);
}

void run_server(char **output, uint64_t *port) {
  int32_t output_fd;
  if (*output == NULL) { output_fd = STDOUT_FILENO; }
  else {
    ENEG(output_fd = open(*output, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH), "Could not open %s for writing! %m\n", *output);
  }
  struct hmc_net_socket_serve e;
  hmc_net_serve(&e, *port);
  hmc_net_read_handshake(&e);
  fprintf(stdout, "\n");
  print_progressbar(0, e.datalen);
  uint32_t clen = 0, readl;
  while ((readl = hmc_net_read(&e))) {
    ENEG(write(output_fd, e.plaintext, readl), "Could not write %u bytes to %s! %m\n", readl, *output);
    clen += readl;
    print_progressbar(clen, e.datalen);
  }
  hmc_net_close_read(&e);
  nob_log(NOB_INFO, "Peer closed connection!\n");
  close(output_fd);
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

  printf("listen: %d\n", *listen);
  printf("key_fpr: %s\n", *recipient);
  printf("port: %zu\n", *port);

  if (*listen) {
    run_server(output, port);
  } else {
    run_client(input, recipient, targetip, port);
  }

  return 0;
}
