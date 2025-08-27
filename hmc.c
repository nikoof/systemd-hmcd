#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <gpgme.h>

#define NOB_IMPLEMENTATION
#include "nob.h"
#define FLAG_IMPLEMENTATION
#include "flag.h"

#define min(a, b) (a < b ? a : b)

#define _EE(op, targ, cmd, res, args...) \
  { if ((cmd) op (targ)) { nob_log(NOB_ERROR, "systemd_hmcd: " res "\n", ##args); exit(EXIT_FAILURE); } }
#define ENEZ(cmd, res, args...) _EE(!=,    0, cmd, res, ##args)
#define ENEG(cmd, res, args...) _EE(< ,    0, cmd, res, ##args)

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

void hmc_print_file_size(Nob_String_Builder *sb, const char* fmt, size_t file_size) {
  // 1 PiB shouldn't fit into a uint64 but alas
  const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB", "EiB", "PiB" };

  size_t index = 0;
  double display_size = (double)file_size;
  while (display_size >= 1024 && index < NOB_ARRAY_LEN(units)) {
    display_size /= 1024;
    index += 1;
  }

  nob_sb_appendf(sb, fmt, display_size, units[index]);
}

void hmc_print_progress_bar(FILE *stream, size_t current, size_t total) {
  static Nob_String_Builder sb = {0};
  sb.count = 0;

  const char *loading_indicator = "-\\|/-";

  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

  // Look at what this bih (@gitRaiku) wrote
  // if (total == 0) { total = current = 0 ? 1 : current; }
  if (total == 0) { total = (current == 0) ? (current = 1) : current; }
  float proc = (float)current / (float)total;
  size_t width = min(w.ws_col - strlen(" | [] 1024.69/1024.69 MiB (100%)"), 60);
  size_t donec = width * current / total;

  nob_sb_appendf(&sb, "\033[2K\033[38;5;2m %c ", loading_indicator[donec % strlen(loading_indicator)]);
  nob_sb_appendf(&sb, "\033[0m[\033[38;5;6m");
  for (size_t i = 0;         i < donec; ++i) { nob_da_append(&sb, '#'); }
  nob_da_append(&sb, donec != width ? '>' : '#');
  for (size_t i = donec + 1; i < width; ++i) { nob_da_append(&sb, '-'); }
  nob_sb_appendf(&sb, "\033[0m] ");
  hmc_print_file_size(&sb, "%.02f", current);
  nob_da_append(&sb, '/');
  hmc_print_file_size(&sb, "%.02f %s", total);
  nob_sb_appendf(&sb, " (%3u%%)\r", (uint32_t)(proc * 100));
  nob_da_append(&sb, '\0');
  fputs(sb.items, stream);
  fflush(stream);
}

ssize_t hmc_crypt_read_net(void *handle, void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  return read(e->net_fd, buffer, size);
}

ssize_t hmc_crypt_write_file(void *handle, const void *buffer, size_t size) {
  Hmc_Data_Server *e = (Hmc_Data_Server*)handle;
  off_t offset = 0;

  static union file_size {
    uint64_t sz;
    uint8_t szes[8];
  } file_size;

  while (e->received_bytes < 8 && size > 0) {
    file_size.szes[e->received_bytes++] = ((char*)buffer)[offset++];
    size -= 1;

    if (size == 0) {
      return offset;
    }

    if (e->received_bytes == 8) {
      e->total_bytes = file_size.sz;

      hmc_print_progress_bar(stderr, e->received_bytes, e->total_bytes);
      ssize_t writel = write(e->file_fd, buffer + offset, size);
      return (writel == -1) ? -1 : offset + writel;
    }
  }

  e->received_bytes += size;
  hmc_print_progress_bar(stderr,e->received_bytes, e->total_bytes);
  return write(e->file_fd, buffer, size);
}

ssize_t hmc_crypt_read_file(void *handle, void *buffer, size_t size) {
  Hmc_Data_Client *e = (Hmc_Data_Client*)handle;
  off_t offset = 0;

  union file_size {
    uint64_t sz;
    uint8_t szes[8];
  } file_size;
  file_size.sz = e->total_bytes;


  while (e->sent_bytes < 8 && size > 0) {
    ((char*)buffer)[offset++] = file_size.szes[e->sent_bytes++];
    size -= 1;

    if (size == 0) {
      return offset;
    }

    if (e->sent_bytes == 8) {
      hmc_print_progress_bar(stderr, e->sent_bytes, e->total_bytes);
      ssize_t readl = read(e->file_fd, buffer + offset, size);
      return (readl == -1) ? -1 : offset + readl;
    }
  }

  hmc_print_progress_bar(stderr, e->sent_bytes, e->total_bytes);
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

void hmc_net_connect(int32_t *fd, char *targetip, uint16_t port) { // TODO: Change name targetip
  char newip[100];
  struct sockaddr_in6 serv_addr6;
  serv_addr6.sin6_family = AF_INET6;
  serv_addr6.sin6_port = htons(port);
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  struct sockaddr *addrp;
  socklen_t addrl;
  int socktype;

  if (inet_pton(AF_INET, targetip, &serv_addr.sin_addr)) {
    addrp = (struct sockaddr*)&serv_addr;
    addrl = sizeof(serv_addr);
    socktype = AF_INET;
  } else if (inet_pton(AF_INET6, targetip, &serv_addr6.sin6_addr)) {
    addrp = (struct sockaddr*)&serv_addr6;
    addrl = sizeof(serv_addr6);
    socktype = AF_INET6;
  } else {
    struct addrinfo hints = {0};
    hints.ai_flags = AI_ALL;
    struct addrinfo *peer; // TODO: Get better messages out of clankka getaddrinfo
    ENEZ(getaddrinfo(targetip, 0, &hints, &peer), "Could not resolve domain name %s!", targetip); 
    ENEZ(getnameinfo(peer->ai_addr, peer->ai_addrlen, newip, sizeof(newip), 0, 0, NI_NUMERICHOST), "Could not get name info for domain %s!", targetip);
    if (inet_pton(AF_INET, newip, &serv_addr.sin_addr)) {
      addrp = (struct sockaddr*)&serv_addr;
      addrl = sizeof(serv_addr);
      socktype = AF_INET;
    } else if (inet_pton(AF_INET6, newip, &serv_addr6.sin6_addr)) {
      addrp = (struct sockaddr*)&serv_addr6;
      addrl = sizeof(serv_addr6);
      socktype = AF_INET6;
    } else { ENEG(-1, "Domain name %s resolved to %s could not be translated into a valid ip address!", targetip, newip); }
    targetip = newip;
  }

  ENEG((*fd = socket(socktype, SOCK_STREAM, 0)), "Could not create connecting socket! %m");

  ENEG(connect(*fd, addrp, addrl), "Could not connect to %s:%hu! %m", targetip, (unsigned short)port);
  nob_log(NOB_INFO, "Connected to remote %s:%hu!", targetip, (unsigned short)port);
}

int32_t hmc_net_serve(int32_t *fd, uint16_t port, uint8_t ipv6) {
  int32_t remote_fd;
  int opt = 0;
  if (ipv6) {
    ENEG((*fd = socket(AF_INET6, SOCK_STREAM, 0)), "Could not create listening socket! %m");
    ENEG(setsockopt(*fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)), "Could not set ipv6 socket options! %m");
  } else {
    ENEG((*fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create listening socket! %m");
  }

  opt = 1;
  ENEG(setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)), "Could not set socket options! %m");

  struct sockaddr_in6 addr6 = {0};
  struct sockaddr_in addr = {0};
  struct sockaddr *addrp;
  socklen_t addrl;

  if (ipv6) {
    addr6.sin6_family = AF_INET6;
    addr6.sin6_addr = in6addr_any;
    addr6.sin6_port = htons(port);
    addrp = (struct sockaddr*)&addr6;
    addrl = sizeof(addr6);
  } else {
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    addrp = (struct sockaddr*)&addr;
    addrl = sizeof(addr);
  }

  ENEG(bind(*fd, addrp, addrl), "Could not bind socket to port %u! %m", port);
  nob_log(NOB_INFO, "systemd_hmcd: Started listening on port %hu", port);

  ENEG(listen(*fd, 1), "Could not set up socket to listen! %m");
  ENEG((remote_fd = accept(*fd, addrp, &addrl)), "Could not accept connection from remote! %m");
  nob_log(NOB_INFO, "systemd_hmcd: Got connection from %u", remote_fd);

  return remote_fd;
}

void hmc_init(Hmc_Context *ctx) {
  setlocale(LC_ALL, "");

  gpgme_check_version(NULL);
  GERR(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "Failed GPGME version check");
  GERR(gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL)), "Failed to set GPGME locale");

  GERR(gpgme_new(&ctx->gpgme_ctx), "Failed to initialize GPGME context");
  gpgme_set_armor(ctx->gpgme_ctx, 0);
}


void hmc_run_client(Hmc_Context ctx, char **input, char **recipient, char **sign, char **targetip, uint64_t *port) {
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

  if (*sign != NULL) {
    gpgme_key_t signing_key[2] = {0};
    GERR(gpgme_get_key(ctx.gpgme_ctx, *sign, &signing_key[0], 0), "Failed to get key with fingerprint %s", *recipient);

    gpgme_signers_clear(ctx.gpgme_ctx);
    GERR(gpgme_signers_add(ctx.gpgme_ctx, signing_key[0]), "Failed to add signing key %s", *sign);

    GERR(gpgme_op_encrypt_sign(ctx.gpgme_ctx, recp_key, GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out), "Failed to encrypt data");
  } else {
    GERR(gpgme_op_encrypt(ctx.gpgme_ctx, recp_key, GPGME_ENCRYPT_ALWAYS_TRUST, data_in, data_out), "Failed to encrypt data");
  }


  hmc_print_progress_bar(stderr, dh.total_bytes, dh.total_bytes);

  close(dh.net_fd);
  close(dh.file_fd);
}

void hmc_run_server(Hmc_Context ctx, char **output, uint64_t *port, uint8_t ipv6) {
  Hmc_Data_Server dh = {0};

  if (*output == NULL) { dh.file_fd = STDOUT_FILENO; }
  else {
    ENEG(dh.file_fd = open(*output, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH), "Could not open %s for writing! %m\n", *output);
  }

  int32_t local_fd;
  dh.net_fd = hmc_net_serve(&local_fd, *port, ipv6);

  gpgme_data_t data_in = {0}, data_out = {0};
  GERR(gpgme_data_new_from_cbs(&data_in, &SERVER_CBS, &dh), "Failed to create GPGME data object");
  GERR(gpgme_data_new_from_cbs(&data_out, &SERVER_CBS, &dh), "Failed to create GPGME data object");

  GERR(gpgme_op_decrypt_verify(ctx.gpgme_ctx, data_in, data_out), "Failed to decrypt data");
  gpgme_verify_result_t verify_result = gpgme_op_verify_result(ctx.gpgme_ctx);
  gpgme_signature_t sig = verify_result->signatures;
  while (sig != NULL) {
    gpgme_sigsum_t sum = sig->summary;

    // TODO: figure out how to interpret these summary flags
    nob_log(NOB_INFO, "%s:", sig->fpr);
    if (sum & GPGME_SIGSUM_VALID)         nob_log(NOB_INFO, "    The signature is fully valid.");
    if (sum & GPGME_SIGSUM_GREEN)         nob_log(NOB_INFO, "    The signature is good.");
    if (sum & GPGME_SIGSUM_RED)           nob_log(NOB_INFO, "    The signature is bad.");
    if (sum & GPGME_SIGSUM_KEY_REVOKED)   nob_log(NOB_INFO, "    One key has been revoked.");
    if (sum & GPGME_SIGSUM_KEY_EXPIRED)   nob_log(NOB_INFO, "    One key has expired.");
    if (sum & GPGME_SIGSUM_SIG_EXPIRED)   nob_log(NOB_INFO, "    The signature has expired.");
    if (sum & GPGME_SIGSUM_KEY_MISSING)   nob_log(NOB_INFO, "    Can't verify: key missing.");
    if (sum & GPGME_SIGSUM_CRL_MISSING)   nob_log(NOB_INFO, "    CRL not available.");
    if (sum & GPGME_SIGSUM_CRL_TOO_OLD)   nob_log(NOB_INFO, "    Available CRL is too old.");
    if (sum & GPGME_SIGSUM_BAD_POLICY)    nob_log(NOB_INFO, "    A policy was not met.");
    if (sum & GPGME_SIGSUM_SYS_ERROR)     nob_log(NOB_INFO, "    A system error occurred.");
    if (sum & GPGME_SIGSUM_TOFU_CONFLICT) nob_log(NOB_INFO, "    Tofu conflict detected.");
    sig = sig->next;
  }


  hmc_print_progress_bar(stderr, dh.total_bytes, dh.total_bytes);
}

void fusage(FILE *stream, const char *progname) {
  fprintf(stream, "usage: %s [OPTIONS]\n", progname);
  fprintf(stream, "OPTIONS:\n");
  flag_print_options(stream);
}

int main(int argc, char **argv) {
  bool *help       = flag_bool  ("help",      false, "Print this message and exit.");
  bool *listen     = flag_bool  ("listen",    false, "Listen or connect.");
  bool *ipv6       = flag_bool  ("6",         NULL,  "Listen on ipv6.");
  char **input     = flag_str   ("input",     NULL,  "Input file. If unspecified, read from stdin.");
  char **output    = flag_str   ("output",    NULL,  "Output file. If unspecified, print to stdout.");
  char **targetip  = flag_str   ("targetip",  NULL,  "Peer ip to connect to.");
  char **recipient = flag_str   ("recipient", NULL,  "GPG fingerprint of recipient key.");
  char **sign      = flag_str   ("sign",      NULL,  "Optional GPG fingerprint of signing key. If unspecified, no signatures are made.");
  uint64_t *port   = flag_uint64("port",      6969,  "Port to listen on.");


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
    hmc_run_server(ctx, output, port, *ipv6);
  } else {
    if (*recipient == NULL || **recipient == '\0') {
      nob_log(NOB_ERROR, "Cannot connect to remote if encryption recipient is unknown!");
      fusage(stderr, argv[0]); exit(EXIT_FAILURE);
    }

    if (*targetip == NULL || **targetip == '\0') {
      nob_log(NOB_ERROR, "Cannot connect to remote if target ip is unknown!");
      fusage(stderr, argv[0]); exit(EXIT_FAILURE);
    }

    hmc_run_client(ctx, input, recipient, sign, targetip, port);
  }

  printf("\n");
  return 0;
}
