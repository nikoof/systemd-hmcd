#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <gpgme.h>

#define NOB_IMPLEMENTATION
#include "nob.h"
#define FLAG_IMPLEMENTATION
#include "flag.h"

#define _EE(op, targ, cmd, res, args...) {if ((cmd) op (targ)) { nob_log(NOB_ERROR, "systemd_hmcd: " res "\n", ##args); exit(EXIT_FAILURE); } }
#define EZERO(cmd, res, args...) _EE(==,    0, cmd, res, ##args)
#define ENULL(cmd, res, args...) _EE(==, NULL, cmd, res, ##args)
#define  ENEZ(cmd, res, args...) _EE(!=,    0, cmd, res, ##args)
#define  ENEG(cmd, res, args...) _EE(< ,    0, cmd, res, ##args)

#define GERR(cmd, fmt, args...) \
  { gpgme_error_t err; if ((err = cmd) != 0) { nob_log(NOB_ERROR, "systemd_hmcd: " fmt " (%s)\n", ##args, gpgme_strerror(err)); } }

typedef struct {
  gpgme_ctx_t gpgme_ctx;
} Hmc_Context;

typedef struct {
  int32_t net_fd;
  int32_t file_fd;

  size_t received_bytes;
  size_t total_bytes;
} Hmc_Data_Server;

typedef struct {
  int32_t net_fd;
  int32_t file_fd;

  size_t sent_bytes;
  size_t total_bytes;
} Hmc_Data_Client;

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

ssize_t hmc_crypt_read_net(void *handle, void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  return read(e->net_fd, buffer, size);
}

ssize_t hmc_crypt_write_file(void *handle, const void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  off_t offset = 0;

  static union file_size {
    uint32_t sz;
    uint8_t szes[4];
  } file_size;

  while (e->received_bytes < 4 && size > 0) {
    file_size.szes[e->received_bytes++] = ((char*)buffer)[offset++];
    size -= 1;

    if (size == 0) {
      return offset;
    }

    if (e->received_bytes == 4) {
      e->total_bytes = ntohl(file_size.sz);

      print_progressbar(e->received_bytes, e->total_bytes);
      ssize_t writel = write(e->file_fd, buffer + offset, size);
      return (writel == -1) ? -1 : offset + writel;
    }
  }

  e->received_bytes += size;
  print_progressbar(e->received_bytes, e->total_bytes);
  return write(e->file_fd, buffer, size);
}

ssize_t hmc_crypt_read_file(void *handle, void *buffer, size_t size) {
  Hmc_Data_Client *e = (Hmc_Data_Client*)handle;
  off_t offset = 0;

  union file_size {
    uint32_t sz;
    uint8_t szes[4];
  } file_size;
  file_size.sz = htonl(e->total_bytes);


  while (e->sent_bytes < 4 && size > 0) {
    ((char*)buffer)[offset++] = file_size.szes[e->sent_bytes++];
    size -= 1;

    if (size == 0) {
      return offset;
    }

    if (e->sent_bytes == 4) {
      print_progressbar(e->sent_bytes, e->total_bytes);
      ssize_t readl = read(e->file_fd, buffer + offset, size);
      return (readl == -1) ? -1 : offset + readl;
    }
  }

  print_progressbar(e->sent_bytes, e->total_bytes);
  e->sent_bytes += size;
  return read(e->file_fd, buffer, size);
}

ssize_t hmc_crypt_write_net(void *handle, const void *buffer, size_t size) {
  Hmc_Data_Client *e = (Hmc_Data_Client*)handle;
  return send(e->net_fd, buffer, size, 0);
}

static struct gpgme_data_cbs SERVER_CBS = {
  .read = &hmc_crypt_read_net,
  .write = &hmc_crypt_write_file,
};

static struct gpgme_data_cbs CLIENT_CBS = {
  .read = &hmc_crypt_read_file,
  .write = &hmc_crypt_write_net,
};

void hmc_init(Hmc_Context *ctx) {
  setlocale(LC_ALL, "");

  gpgme_check_version(NULL);
  GERR(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "Failed GPGME version check");
  GERR(gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL)), "Failed to set GPGME locale");

  GERR(gpgme_new(&ctx->gpgme_ctx), "Failed to initialize GPGME context");
  gpgme_set_armor(ctx->gpgme_ctx, 1);
}

void hmc_net_connect(int32_t *fd, const char *targetip, uint16_t port) {
  ENEG((*fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create connecting socket! %m");
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  ENEG(inet_pton(AF_INET, targetip, &serv_addr.sin_addr) - 1, "Could not parse address %s! %s", targetip, (errno == EAFNOSUPPORT) ? strerror(errno) : "Invalid address");
  ENEG(connect(*fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)), "Could not connect to %s:%hu! %m", targetip, (unsigned short)port);
  nob_log(NOB_INFO, "Connected to remote %s:%hu!", targetip, (unsigned short)port);
}

int32_t hmc_net_serve(int32_t *fd, uint16_t port) {
  /// TODO: Support ipv6
  int32_t remote_fd;
  ENEG((*fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create listening socket! %m");

  int opt = 1;
  ENEG(setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)), "Could not set socket options! %m");

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  ENEG(bind(*fd, (struct sockaddr*)&addr, sizeof(addr)), "Could not bind socket to port %u! %m", port);
  nob_log(NOB_INFO, "systemd_hmcd: Started listening on port %hu", port);

  ENEG(listen(*fd, 1), "Could not set up socket to listen! %m");
  socklen_t addrl = sizeof(addr);
  ENEG((remote_fd = accept(*fd, (struct sockaddr*)&addr, &addrl)), "Could not accept connection from remote! %m");
  nob_log(NOB_INFO, "systemd_hmcd: Got connection from %u", remote_fd);

  return remote_fd;
}

void run_client(Hmc_Context ctx, char **input, char **recipient, char **targetip, uint64_t *port) {
  Hmc_Data_Client dh = {0};

  if (*input == NULL) {
    dh.file_fd = STDIN_FILENO;
  } else {
    ENEG((dh.file_fd = open(*input, O_RDONLY)), "Could not open file %s! %m", *input);
    struct stat st; stat(*input, &st); dh.total_bytes = st.st_size;
  }

  hmc_net_connect(&dh.net_fd, *targetip, *port);

  gpgme_data_t data_in = {0}, data_out = {0};
  GERR(gpgme_data_new_from_cbs(&data_in, &CLIENT_CBS, &dh), "Failed to create GPGME data object");
  GERR(gpgme_data_new_from_cbs(&data_out, &CLIENT_CBS, &dh), "Failed to create GPGME data object");

  gpgme_key_t recp_key[2] = {0};
  GERR(gpgme_get_key(ctx.gpgme_ctx, *recipient, &recp_key[0], 0), "Failed to get key with fingerprint %s", *recipient);
  GERR(gpgme_op_encrypt(ctx.gpgme_ctx, recp_key, GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out), "Failed to encrypt data");

  close(dh.net_fd);
  close(dh.file_fd);
}

void run_server(Hmc_Context ctx, char **output, uint64_t *port) {
  Hmc_Data_Server dh = {0};

  if (*output == NULL) { dh.file_fd = STDOUT_FILENO; }
  else {
    ENEG(dh.file_fd = open(*output, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH), "Could not open %s for writing! %m\n", *output);
  }

  int32_t local_fd;
  dh.net_fd = hmc_net_serve(&local_fd, *port);

  gpgme_data_t data_in = {0}, data_out = {0};
  GERR(gpgme_data_new_from_cbs(&data_in, &SERVER_CBS, &dh), "Failed to create GPGME data object");
  GERR(gpgme_data_new_from_cbs(&data_out, &SERVER_CBS, &dh), "Failed to create GPGME data object");

  GERR(gpgme_op_decrypt(ctx.gpgme_ctx, data_in, data_out), "Failed to decrypt data");
}

void fusage(FILE *stream, const char *progname) {
  fprintf(stream, "usage: %s [OPTIONS]\n", progname);
  fprintf(stream, "OPTIONS:\n");
  flag_print_options(stream);
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
    fusage(stderr, argv[0]);
    flag_print_error(stderr);
    exit(EXIT_FAILURE);
  }

  if (*help) {
    fusage(stdout, argv[0]);
    exit(EXIT_SUCCESS);
  }

  if (!(*recipient) && !(*listen)) {
    fusage(stderr, argv[0]);
    nob_log(NOB_ERROR, "Missing required parameter `-recipient`");
    exit(EXIT_FAILURE);
  }

  Hmc_Context ctx = {0};
  hmc_init(&ctx);

  if (*listen) {
    run_server(ctx, output, port);
  } else {
    if (*recipient == NULL || **recipient == '\0') {
      nob_log(NOB_ERROR, "Cannot connect to remote if encryption recipient is unknown!");
      fusage(stderr, argv[0]); exit(EXIT_FAILURE);
    }

    if (*targetip == NULL || **targetip == '\0') {
      nob_log(NOB_ERROR, "Cannot connect to remote if target ip is unknown!");
      fusage(stderr, argv[0]); exit(EXIT_FAILURE);
    }

    run_client(ctx, input, recipient, targetip, port);
  }

  return 0;
}
