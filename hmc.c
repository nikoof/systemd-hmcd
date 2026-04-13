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

void fusage(FILE *stream) {
  fprintf(stream, "usage: %s [OPTIONS]\n", flag_program_name());
  fprintf(stream, "OPTIONS:\n");
  flag_print_options(stream);
}

void print_jarvis(void);
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
    fusage(stderr);
    flag_print_error(stderr);
    exit(EXIT_FAILURE);
  }

  if (*help) {
    fusage(stdout);
    exit(EXIT_SUCCESS);
  }

  if (!(*recipient) && !(*listen)) {
    fusage(stderr);
    nob_log(NOB_ERROR, "Missing required parameter `-recipient`");
    exit(EXIT_FAILURE);
  }

  print_jarvis();

  Hmc_Context ctx = {0};
  hmc_init(&ctx);

  if (*listen) {
    hmc_run_server(ctx, output, port, *ipv6);
  } else {
    if (*recipient == NULL || **recipient == '\0') {
      nob_log(NOB_ERROR, "Cannot connect to remote if encryption recipient is unknown!");
      fusage(stderr); exit(EXIT_FAILURE);
    }

    if (*targetip == NULL || **targetip == '\0') {
      nob_log(NOB_ERROR, "Cannot connect to remote if target ip is unknown!");
      fusage(stderr); exit(EXIT_FAILURE);
    }

    hmc_run_client(ctx, input, recipient, sign, targetip, port);
  }

  printf("\n");
  return 0;
}


void print_jarvis() {
    printf("Welcome home Sir.\n");
    printf(
        "\n\x1b[38;2;8;5;1;48;2;5;0;4m\xE2\x96\x84\x1b[38;2;8;1;0;48;2;6;2;1m\xE2\x96\x84\x1b[38;2;10;4;4;48;2;6;0;1m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;6;3;0m\xE2\x96\x84\x1b[38;2;9;4;3;48;2;7;1;1m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;6;3;1m\xE2\x96\x84\x1b[38;2;9;3;0;48;2;4;2;1m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;9;4;2;48;2;3;1;1m\xE2\x96\x84\x1b[38;2;16;6;4;48;2;3;4;1m\xE2\x96\x84\x1b[38;2;11;6;3;48;2;3;0;0m\xE2\x96\x84\x1b[38;2;34;3;11;48;2;16;4;6m\xE2\x96\x84\x1b[38;2;41;34;18;48;2;69;36;30m\xE2\x96\x84\x1b[38;2;111;72;54;48;2;113;68;56m\xE2\x96\x84\x1b[38;2;165;98;67;48;2;131;73;58m\xE2\x96\x84\x1b[38;2;176;108;92;48;2;191;128;95m\xE2\x96\x84\x1b[38;2;213;159;115;48;2;232;187;128m\xE2\x96\x84\x1b[38;2;230;185;141;48;2;233;181;127m\xE2\x96\x84\x1b[38;2;235;195;148;48;2;235;201;157m\xE2\x96\x84\x1b[38;2;246;202;159;48;2;246;214;176m\xE2\x96\x84\x1b[38;2;248;222;188;48;2;249;222;191m\xE2\x96\x84\x1b[38;2;250;222;185;48;2;248;221;199m\xE2\x96\x84\x1b[38;2;252;218;179;48;2;248;221;191m\xE2\x96\x84\x1b[38;2;250;218;182;48;2;248;222;188m\xE2\x96\x84\x1b[38;2;243;198;160;48;2;248;227;206m\xE2\x96\x84\x1b[38;2;250;218;166;48;2;250;227;195m\xE2\x96\x84\x1b[38;2;247;212;176;48;2;248;229;199m\xE2\x96\x84\x1b[38;2;247;221;194;48;2;247;226;204m\xE2\x96\x84\x1b[38;2;248;220;178;48;2;251;235;210m\xE2\x96\x84\x1b[38;2;205;169;122;48;2;248;227;199m\xE2\x96\x84\x1b[38;2;123;105;91;48;2;241;193;160m\xE2\x96\x84\x1b[38;2;102;72;71;48;2;233;190;130m\xE2\x96\x84\x1b[38;2;51;28;25;48;2;181;131;88m\xE2\x96\x84\x1b[38;2;20;4;4;48;2;150;100;86m\xE2\x96\x84\x1b[38;2;31;9;16;48;2;148;100;69m\xE2\x96\x84\x1b[38;2;113;63;67;48;2;142;88;68m\xE2\x96\x84\x1b[38;2;74;39;44;48;2;95;53;52m\xE2\x96\x84\x1b[38;2;22;1;9;48;2;26;9;8m\xE2\x96\x84\x1b[38;2;9;4;2;48;2;4;0;1m\xE2\x96\x84\x1b[38;2;8;1;1;48;2;14;5;3m\xE2\x96\x84\x1b[38;2;6;5;3;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;11;3;4;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;9;0;1;48;2;6;3;1m\xE2\x96\x84\x1b[38;2;7;6;2;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;8;2;0;48;2;7;3;1m\xE2\x96\x84\x1b[38;2;7;4;2;48;2;7;0;1m\xE2\x96\x84\x1b[38;2;8;2;0;48;2;4;3;1m\xE2\x96\x84\x1b[38;2;9;4;1;48;2;5;1;0m\xE2\x96\x84\x1b[38;2;9;0;1;48;2;4;3;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;8;4;1;48;2;5;1;3m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;5;4;2m\xE2\x96\x84\x1b[38;2;23;7;7;48;2;4;0;2m\xE2\x96\x84\x1b[38;2;19;20;7;48;2;3;5;0m\xE2\x96\x84\x1b[38;2;65;69;63;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;18;13;4;48;2;15;6;3m\xE2\x96\x84\x1b[38;2;15;4;8;48;2;10;2;0m\xE2\x96\x84\x1b[38;2;10;1;4;48;2;46;33;21m\xE2\x96\x84\x1b[38;2;10;7;3;48;2;72;48;45m\xE2\x96\x84\x1b[38;2;26;1;0;48;2;43;74;51m\xE2\x96\x84\x1b[38;2;17;7;5;48;2;11;13;7m\xE2\x96\x84\x1b[38;2;16;0;1;48;2;71;75;64m\xE2\x96\x84\x1b[38;2;31;6;7;48;2;72;114;101m\xE2\x96\x84\x1b[38;2;13;0;8;48;2;69;71;58m\xE2\x96\x84\x1b[38;2;14;6;8;48;2;67;26;13m\xE2\x96\x84\x1b[38;2;16;0;4;48;2;120;81;64m\xE2\x96\x84\x1b[38;2;44;26;24;48;2;150;113;91m\xE2\x96\x84\x1b[38;2;36;9;16;48;2;166;117;93m\xE2\x96\x84\x1b[38;2;60;34;34;48;2;219;173;129m\xE2\x96\x84\x1b[38;2;57;32;30;48;2;243;196;156m\xE2\x96\x84\x1b[38;2;113;71;73;48;2;241;205;170m\xE2\x96\x84\x1b[38;2;198;155;131;48;2;247;211;167m\xE2\x96\x84\x1b[38;2;228;174;139;48;2;247;210;161m\xE2\x96\x84\x1b[38;2;236;189;136;48;2;247;204;159m\xE2\x96\x84\x1b[38;2;244;192;143;48;2;247;219;169m\xE2\x96\x84\x1b[38;2;197;131;96;48;2;246;206;152m\xE2\x96\x84\x1b[38;2;145;89;72;48;2;226;184;148m\xE2\x96\x84\x1b[38;2;102;54;57;48;2;134;117;91m\xE2\x96\x84\x1b[38;2;81;42;49;48;2;52;23;17m\xE2\x96\x84\x1b[38;2;73;33;35;48;2;32;9;12m\xE2\x96\x84\x1b[38;2;102;61;63;48;2;20;2;2m\xE2\x96\x84\x1b[38;2;78;52;49;48;2;47;14;18m\xE2\x96\x84\x1b[38;2;79;44;48;48;2;21;3;5m\xE2\x96\x84\x1b[38;2;104;62;56;48;2;15;5;2m\xE2\x96\x84\x1b[38;2;76;36;37;48;2;25;3;2m\xE2\x96\x84\x1b[38;2;68;31;27;48;2;17;6;3m\xE2\x96\x84\x1b[38;2;70;34;34;48;2;75;40;33m\xE2\x96\x84\x1b[38;2;28;2;6;48;2;23;7;1m\xE2\x96\x84\x1b[38;2;14;6;3;48;2;11;2;0m\xE2\x96\x84\x1b[38;2;9;17;10;48;2;51;54;41m\xE2\x96\x84\x1b[38;2;12;22;16;48;2;5;3;6m\xE2\x96\x84\x1b[38;2;237;230;214;48;2;28;14;22m\xE2\x96\x84\x1b[38;2;21;8;9;48;2;22;5;6m\xE2\x96\x84\x1b[38;2;30;18;17;48;2;2;6;2m\xE2\x96\x84\x1b[38;2;9;6;2;48;2;6;1;3m\xE2\x96\x84\x1b[38;2;11;0;0;48;2;8;3;3m\xE2\x96\x84\x1b[38;2;13;5;2;48;2;4;1;4m\xE2\x96\x84\x1b[38;2;10;2;0;48;2;3;5;4m\xE2\x96\x84\x1b[38;2;10;6;3;48;2;6;1;3m\xE2\x96\x84\x1b[38;2;11;0;0;48;2;3;5;2m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;14;4;2;48;2;11;1;4m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;78;87;76m\xE2\x96\x84\x1b[38;2;9;6;1;48;2;148;165;157m\xE2\x96\x84\x1b[38;2;11;1;0;48;2;14;7;5m\xE2\x96\x84\x1b[38;2;8;6;2;48;2;8;0;4m\xE2\x96\x84\x1b[38;2;12;1;0;48;2;5;3;1m\xE2\x96\x84\x1b[38;2;9;4;1;48;2;8;0;2m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;5;5;0m\xE2\x96\x84\x1b[38;2;10;5;1;48;2;6;0;6m\xE2\x96\x84\x1b[38;2;11;1;0;48;2;4;5;1m\xE2\x96\x84\x1b[38;2;9;5;2;48;2;5;0;3m\xE2\x96\x84\x1b[38;2;16;0;1;48;2;16;5;3m\xE2\x96\x84\x1b[38;2;50;25;15;48;2;31;6;7m\xE2\x96\x84\x1b[38;2;70;35;37;48;2;28;8;8m\xE2\x96\x84\x1b[38;2;44;17;27;48;2;72;41;37m\xE2\x96\x84\x1b[38;2;46;18;24;48;2;69;35;35m\xE2\x96\x84\x1b[38;2;139;126;104;48;2;9;1;3m\xE2\x96\x84\x1b[38;2;15;0;2;48;2;2;0;0m\xE2\x96\x84\x1b[38;2;21;1;6;48;2;15;1;0m\xE2\x96\x84\x1b[38;2;206;183;172;48;2;54;20;26m\xE2\x96\x84\x1b[38;2;140;78;72;48;2;74;39;40m\xE2\x96\x84\x1b[38;2;163;128;104;48;2;93;53;47m\xE2\x96\x84\x1b[38;2;101;58;56;48;2;128;72;61m\xE2\x96\x84\x1b[38;2;212;146;99;48;2;216;166;108m\xE2\x96\x84\x1b[38;2;242;189;149;48;2;237;200;147m\xE2\x96\x84\x1b[38;2;152;94;78;48;2;179;121;83m\xE2\x96\x84\x1b[38;2;161;119;103;48;2;125;65;67m\xE2\x96\x84\x1b[38;2;152;103;89;48;2;114;65;66m\xE2\x96\x84\x1b[38;2;144;70;79;48;2;145;85;89m\xE2\x96\x84\x1b[38;2;232;220;195;48;2;131;101;85m\xE2\x96\x84\x1b[38;2;68;41;37;48;2;76;73;67m\xE2\x96\x84\x1b[38;2;79;43;49;48;2;10;4;2m\xE2\x96\x84\x1b[38;2;178;134;121;48;2;122;105;86m\xE2\x96\x84\x1b[38;2;82;39;49;48;2;19;0;6m\xE2\x96\x84\x1b[38;2;117;62;57;48;2;78;42;43m\xE2\x96\x84\x1b[38;2;142;88;70;48;2;117;64;55m\xE2\x96\x84\x1b[38;2;80;37;45;48;2;78;43;44m\xE2\x96\x84\x1b[38;2;29;10;3;48;2;21;3;3m\xE2\x96\x84\x1b[38;2;14;5;1;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;2;1;2;48;2;3;4;4m\xE2\x96\x84\x1b[38;2;9;5;2;48;2;7;0;2m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;17;8;9m\xE2\x96\x84\x1b[38;2;10;5;2;48;2;16;1;1m\xE2\x96\x84\x1b[38;2;11;1;2;48;2;15;5;5m\xE2\x96\x84\x1b[38;2;13;8;4;48;2;13;1;2m\xE2\x96\x84\x1b[38;2;11;0;1;48;2;14;4;5m\xE2\x96\x84\x1b[38;2;9;4;3;48;2;27;18;12m\xE2\x96\x84\x1b[38;2;36;70;70;48;2;18;3;6m\xE2\x96\x84\x1b[38;2;219;215;210;48;2;7;0;1m\xE2\x96\x84\x1b[38;2;33;22;24;48;2;5;4;2m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;9;5;2;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;7;3;2m\xE2\x96\x84\x1b[38;2;9;5;1;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;11;0;0;48;2;3;6;2m\xE2\x96\x84\x1b[38;2;7;6;2;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;6;4;2m\xE2\x96\x84\x1b[38;2;8;5;2;48;2;4;2;0m\xE2\x96\x84\x1b[38;2;11;1;0;48;2;5;4;2m\xE2\x96\x84\x1b[38;2;8;6;2;48;2;4;2;3m\xE2\x96\x84\x1b[38;2;9;2;0;48;2;4;4;2m\xE2\x96\x84\x1b[38;2;8;5;3;48;2;7;0;2m\xE2\x96\x84\x1b[38;2;16;1;4;48;2;20;4;4m\xE2\x96\x84\x1b[38;2;56;26;23;48;2;68;34;24m\xE2\x96\x84\x1b[38;2;131;84;68;48;2;109;61;54m\xE2\x96\x84\x1b[38;2;130;100;83;48;2;101;63;59m\xE2\x96\x84\x1b[38;2;64;37;37;48;2;136;97;97m\xE2\x96\x84\x1b[38;2;113;62;70;48;2;177;161;137m\xE2\x96\x84\x1b[38;2;66;28;30;48;2;41;18;23m\xE2\x96\x84\x1b[38;2;152;100;97;48;2;70;31;39m\xE2\x96\x84\x1b[38;2;194;126;125;48;2;208;181;161m\xE2\x96\x84\x1b[38;2;215;169;139;48;2;204;161;145m\xE2\x96\x84\x1b[38;2;229;198;153;48;2;200;166;113m\xE2\x96\x84\x1b[38;2;200;149;102;48;2;163;123;105m\xE2\x96\x84\x1b[38;2;245;206;167;48;2;238;189;133m\xE2\x96\x84\x1b[38;2;247;206;163;48;2;238;194;151m\xE2\x96\x84\x1b[38;2;229;186;140;48;2;205;151;119m\xE2\x96\x84\x1b[38;2;240;198;163;48;2;239;210;171m\xE2\x96\x84\x1b[38;2;235;210;181;48;2;240;218;180m\xE2\x96\x84\x1b[38;2;213;162;135;48;2;209;172;150m\xE2\x96\x84\x1b[38;2;179;122;93;48;2;178;134;118m\xE2\x96\x84\x1b[38;2;167;118;105;48;2;222;195;184m\xE2\x96\x84\x1b[38;2;134;85;89;48;2;214;187;175m\xE2\x96\x84\x1b[38;2;94;54;50;48;2;133;72;74m\xE2\x96\x84\x1b[38;2;150;106;86;48;2;85;51;52m\xE2\x96\x84\x1b[38;2;208;157;118;48;2;144;97;81m\xE2\x96\x84\x1b[38;2;177;112;90;48;2;158;104;75m\xE2\x96\x84\x1b[38;2;81;39;42;48;2;73;34;35m\xE2\x96\x84\x1b[38;2;20;14;3;48;2;23;6;7m\xE2\x96\x84\x1b[38;2;5;5;3;48;2;5;1;0m\xE2\x96\x84\x1b[38;2;6;2;1;48;2;4;4;6m\xE2\x96\x84\x1b[38;2;8;5;2;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;5;4;2m\xE2\x96\x84\x1b[38;2;11;4;2;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;4;5;2m\xE2\x96\x84\x1b[38;2;10;5;4;48;2;18;2;2m\xE2\x96\x84\x1b[38;2;26;20;16;48;2;6;3;1m\xE2\x96\x84\x1b[38;2;8;4;3;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;11;1;0;48;2;10;5;2m\xE2\x96\x84\x1b[38;2;10;5;2;48;2;16;9;2m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;6;4;2m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;8;4;1;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;9;2;0;48;2;6;2;1m\xE2\x96\x84\x1b[38;2;9;4;1;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;8;1;0;48;2;4;3;1m\xE2\x96\x84\x1b[38;2;9;4;1;48;2;6;0;1m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;9;2;2;48;2;5;1;1m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;5;3;1m\xE2\x96\x84\x1b[38;2;8;3;2;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;8;2;0;48;2;4;4;2m\xE2\x96\x84\x1b[38;2;7;3;1;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;7;3;0m\xE2\x96\x84\x1b[38;2;17;3;0;48;2;29;8;4m\xE2\x96\x84\x1b[38;2;118;73;65;48;2;139;81;70m\xE2\x96\x84\x1b[38;2;179;122;87;48;2;160;116;80m\xE2\x96\x84\x1b[38;2;191;135;104;48;2;144;100;93m\xE2\x96\x84\x1b[38;2;182;126;104;48;2;110;65;61m\xE2\x96\x84\x1b[38;2;168;127;104;48;2;128;81;78m\xE2\x96\x84\x1b[38;2;196;146;114;48;2;162;97;92m\xE2\x96\x84\x1b[38;2;229;190;156;48;2;196;149;121m\xE2\x96\x84\x1b[38;2;242;202;152;48;2;230;199;169m\xE2\x96\x84\x1b[38;2;218;169;125;48;2;232;192;147m\xE2\x96\x84\x1b[38;2;185;123;84;48;2;202;144;107m\xE2\x96\x84\x1b[38;2;248;225;209;48;2;248;221;188m\xE2\x96\x84\x1b[38;2;247;220;179;48;2;250;220;182m\xE2\x96\x84\x1b[38;2;211;147;101;48;2;220;164;109m\xE2\x96\x84\x1b[38;2;222;163;124;48;2;234;201;146m\xE2\x96\x84\x1b[38;2;231;176;126;48;2;246;210;164m\xE2\x96\x84\x1b[38;2;246;208;156;48;2;238;201;160m\xE2\x96\x84\x1b[38;2;233;192;129;48;2;208;163;113m\xE2\x96\x84\x1b[38;2;238;188;143;48;2;209;162;136m\xE2\x96\x84\x1b[38;2;236;195;149;48;2;198;155;137m\xE2\x96\x84\x1b[38;2;234;192;134;48;2;201;153;128m\xE2\x96\x84\x1b[38;2;236;188;141;48;2;216;169;121m\xE2\x96\x84\x1b[38;2;203;137;102;48;2;223;171;121m\xE2\x96\x84\x1b[38;2;153;101;80;48;2;163;101;74m\xE2\x96\x84\x1b[38;2;42;14;28;48;2;68;28;31m\xE2\x96\x84\x1b[38;2;18;4;3;48;2;14;6;6m\xE2\x96\x84\x1b[38;2;5;4;2;48;2;3;0;0m\xE2\x96\x84\x1b[38;2;2;0;1;48;2;3;3;3m\xE2\x96\x84\x1b[38;2;9;4;0;48;2;8;0;2m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;9;4;2;48;2;6;1;0m\xE2\x96\x84\x1b[38;2;9;0;0;48;2;5;3;1m\xE2\x96\x84\x1b[38;2;81;79;76;48;2;10;0;0m\xE2\x96\x84\x1b[38;2;5;9;0;48;2;19;12;8m\xE2\x96\x84\x1b[38;2;9;3;0;48;2;6;0;2m\xE2\x96\x84\x1b[38;2;11;3;1;48;2;4;3;2m\xE2\x96\x84\x1b[38;2;9;4;4;48;2;6;0;1m\xE2\x96\x84\x1b[38;2;10;1;0;48;2;5;4;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;7;3;0;48;2;6;0;2m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;4;3;1m\xE2\x96\x84\x1b[38;2;5;4;2;48;2;5;0;1m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;4;4;0m\xE2\x96\x84\x1b[38;2;8;4;1;48;2;5;0;2m\xE2\x96\x84\x1b[38;2;8;1;0;48;2;4;3;1m\xE2\x96\x84\x1b[38;2;10;2;0;48;2;6;1;0m\xE2\x96\x84\x1b[38;2;7;2;0;48;2;2;3;1m\xE2\x96\x84\x1b[38;2;8;4;1;48;2;7;0;2m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;4;4;2m\xE2\x96\x84\x1b[38;2;7;4;3;48;2;5;0;4m\xE2\x96\x84\x1b[38;2;1;0;0;48;2;2;2;2m\xE2\x96\x84\x1b[38;2;12;3;2;48;2;13;2;1m\xE2\x96\x84\x1b[38;2;70;32;31;48;2;73;28;27m\xE2\x96\x84\x1b[38;2;133;91;69;48;2;170;105;82m\xE2\x96\x84\x1b[38;2;199;143;103;48;2;219;169;134m\xE2\x96\x84\x1b[38;2;219;163;129;48;2;215;169;128m\xE2\x96\x84\x1b[38;2;230;191;153;48;2;224;172;133m\xE2\x96\x84\x1b[38;2;232;193;154;48;2;228;184;144m\xE2\x96\x84\x1b[38;2;247;209;170;48;2;245;209;172m\xE2\x96\x84\x1b[38;2;234;185;136;48;2;227;181;128m\xE2\x96\x84\x1b[38;2;170;113;86;48;2;191;130;100m\xE2\x96\x84\x1b[38;2;204;140;95;48;2;181;125;84m\xE2\x96\x84\x1b[38;2;248;226;201;48;2;249;225;199m\xE2\x96\x84\x1b[38;2;242;200;161;48;2;244;201;147m\xE2\x96\x84\x1b[38;2;191;110;87;48;2;195;128;91m\xE2\x96\x84\x1b[38;2;193;132;93;48;2;203;136;102m\xE2\x96\x84\x1b[38;2;206;155;102;48;2;219;166;120m\xE2\x96\x84\x1b[38;2;242;200;154;48;2;240;194;141m\xE2\x96\x84\x1b[38;2;245;210;174;48;2;243;202;147m\xE2\x96\x84\x1b[38;2;249;218;187;48;2;245;210;169m\xE2\x96\x84\x1b[38;2;246;211;173;48;2;248;218;180m\xE2\x96\x84\x1b[38;2;242;194;156;48;2;245;203;162m\xE2\x96\x84\x1b[38;2;226;169;121;48;2;226;178;125m\xE2\x96\x84\x1b[38;2;173;113;88;48;2;200;143;103m\xE2\x96\x84\x1b[38;2;65;31;31;48;2;114;58;50m\xE2\x96\x84\x1b[38;2;57;20;25;48;2;48;19;22m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;10;2;4m\xE2\x96\x84\x1b[38;2;3;4;0;48;2;2;0;0m\xE2\x96\x84\x1b[38;2;4;0;1;48;2;1;3;3m\xE2\x96\x84\x1b[38;2;7;2;2;48;2;6;0;3m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;8;3;1;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;8;0;1;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;26;21;16;48;2;19;14;7m\xE2\x96\x84\x1b[38;2;3;0;3;48;2;12;7;2m\xE2\x96\x84\x1b[38;2;5;4;2;48;2;7;0;3m\xE2\x96\x84\x1b[38;2;11;0;0;48;2;4;3;0m\xE2\x96\x84\x1b[38;2;9;4;1;48;2;8;0;2m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;4;4;2m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;7;2;0;48;2;5;0;3m\xE2\x96\x84\x1b[38;2;9;0;0;48;2;7;1;2m\xE2\x96\x84\x1b[38;2;5;3;0;48;2;7;0;1m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;7;2;2m\xE2\x96\x84\x1b[38;2;7;3;0;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;13;3;0;48;2;6;3;0m\xE2\x96\x84\x1b[38;2;13;2;1;48;2;22;7;1m\xE2\x96\x84\x1b[38;2;24;42;40;48;2;101;77;59m\xE2\x96\x84\x1b[38;2;235;207;145;48;2;6;10;2m\xE2\x96\x84\x1b[38;2;42;34;26;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;7;2;3;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;0;0;2;48;2;2;2;1m\xE2\x96\x84\x1b[38;2;2;2;0;48;2;17;0;0m\xE2\x96\x84\x1b[38;2;32;6;1;48;2;51;14;16m\xE2\x96\x84\x1b[38;2;97;40;40;48;2;108;58;53m\xE2\x96\x84\x1b[38;2;156;99;71;48;2;184;125;88m\xE2\x96\x84\x1b[38;2;196;128;94;48;2;220;159;119m\xE2\x96\x84\x1b[38;2;229;176;139;48;2;232;172;136m\xE2\x96\x84\x1b[38;2;240;197;162;48;2;240;193;160m\xE2\x96\x84\x1b[38;2;239;198;166;48;2;249;209;173m\xE2\x96\x84\x1b[38;2;226;176;120;48;2;234;191;147m\xE2\x96\x84\x1b[38;2;169;117;90;48;2;152;106;85m\xE2\x96\x84\x1b[38;2;230;169;126;48;2;222;167;109m\xE2\x96\x84\x1b[38;2;248;230;211;48;2;249;226;200m\xE2\x96\x84\x1b[38;2;246;230;216;48;2;245;208;170m\xE2\x96\x84\x1b[38;2;230;167;119;48;2;211;148;109m\xE2\x96\x84\x1b[38;2;214;152;117;48;2;209;152;123m\xE2\x96\x84\x1b[38;2;208;142;115;48;2;211;155;111m\xE2\x96\x84\x1b[38;2;248;217;178;48;2;251;220;168m\xE2\x96\x84\x1b[38;2;225;173;114;48;2;248;208;159m\xE2\x96\x84\x1b[38;2;210;149;110;48;2;245;207;170m\xE2\x96\x84\x1b[38;2;226;173;122;48;2;246;206;169m\xE2\x96\x84\x1b[38;2;223;162;116;48;2;230;179;128m\xE2\x96\x84\x1b[38;2;190;112;83;48;2;214;146;110m\xE2\x96\x84\x1b[38;2;112;55;50;48;2;153;98;77m\xE2\x96\x84\x1b[38;2;77;36;38;48;2;52;22;19m\xE2\x96\x84\x1b[38;2;19;6;5;48;2;35;4;6m\xE2\x96\x84\x1b[38;2;2;0;0;48;2;1;2;2m\xE2\x96\x84\x1b[38;2;1;3;0;48;2;2;0;0m\xE2\x96\x84\x1b[38;2;1;0;0;48;2;2;2;2m\xE2\x96\x84\x1b[38;2;6;2;0;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;3;4;0m\xE2\x96\x84\x1b[38;2;6;3;0;48;2;5;0;1m\xE2\x96\x84\x1b[38;2;9;0;0;48;2;108;101;89m\xE2\x96\x84\x1b[38;2;15;11;5;48;2;38;36;32m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;1;2;1m\xE2\x96\x84\x1b[38;2;7;2;0;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;7;2;0;48;2;5;0;3m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;4;3;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;6;2;0;48;2;5;1;2m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;5;1;1m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;4;0;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;4;2;0m\xE2\x96\x84\x1b[38;2;22;28;13;48;2;21;10;6m\xE2\x96\x84\x1b[38;2;30;38;19;48;2;13;3;2m\xE2\x96\x84\x1b[38;2;41;51;29;48;2;47;99;118m\xE2\x96\x84\x1b[38;2;99;179;157;48;2;58;118;124m\xE2\x96\x84\x1b[38;2;68;135;132;48;2;34;76;84m\xE2\x96\x84\x1b[38;2;53;92;73;48;2;34;56;40m\xE2\x96\x84\x1b[38;2;0;2;5;48;2;6;0;0m\xE2\x96\x84\x1b[38;2;1;0;0;48;2;1;1;1m\xE2\x96\x84\x1b[38;2;1;1;1;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;1;0;0;48;2;27;2;2m\xE2\x96\x84\x1b[38;2;56;22;24;48;2;70;35;31m\xE2\x96\x84\x1b[38;2;68;29;22;48;2;118;62;62m\xE2\x96\x84\x1b[38;2;166;106;91;48;2;174;116;89m\xE2\x96\x84\x1b[38;2;205;143;112;48;2;228;172;136m\xE2\x96\x84\x1b[38;2;218;158;116;48;2;236;183;148m\xE2\x96\x84\x1b[38;2;231;181;126;48;2;230;182;133m\xE2\x96\x84\x1b[38;2;225;152;117;48;2;231;189;146m\xE2\x96\x84\x1b[38;2;126;67;76;48;2;136;87;75m\xE2\x96\x84\x1b[38;2;211;156;114;48;2;232;186;137m\xE2\x96\x84\x1b[38;2;253;220;182;48;2;244;227;211m\xE2\x96\x84\x1b[38;2;246;213;170;48;2;248;232;216m\xE2\x96\x84\x1b[38;2;235;187;130;48;2;241;195;157m\xE2\x96\x84\x1b[38;2;117;58;57;48;2;160;101;71m\xE2\x96\x84\x1b[38;2;128;74;72;48;2;196;133;97m\xE2\x96\x84\x1b[38;2;219;156;112;48;2;233;184;141m\xE2\x96\x84\x1b[38;2;202;133;102;48;2;227;165;114m\xE2\x96\x84\x1b[38;2;193;132;103;48;2;220;169;110m\xE2\x96\x84\x1b[38;2;194;143;106;48;2;152;86;70m\xE2\x96\x84\x1b[38;2;122;58;47;48;2;182;110;76m\xE2\x96\x84\x1b[38;2;119;74;50;48;2;160;107;79m\xE2\x96\x84\x1b[38;2;64;28;33;48;2;81;32;34m\xE2\x96\x84\x1b[38;2;42;11;9;48;2;58;30;29m\xE2\x96\x84\x1b[38;2;1;2;2;48;2;3;0;1m\xE2\x96\x84\x1b[38;2;1;1;0;48;2;0;2;1m\xE2\x96\x84\x1b[38;2;2;2;0;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;5;2;0;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;7;0;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;3;1;0m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;11;1;2m\xE2\x96\x84\x1b[38;2;12;2;0;48;2;14;10;6m\xE2\x96\x84\x1b[38;2;23;1;6;48;2;10;0;1m\xE2\x96\x84\x1b[38;2;13;1;1;48;2;6;0;1m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;5;3;0m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;6;0;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;3;2;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;5;3;0;48;2;6;1;0m\xE2\x96\x84\x1b[48;2;6;1;0m \x1b[38;2;4;1;0;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;7;2;0m\xE2\x96\x84\x1b[38;2;28;49;36;48;2;36;48;23m\xE2\x96\x84\x1b[38;2;9;5;7;48;2;22;17;8m\xE2\x96\x84\x1b[38;2;37;13;3;48;2;31;12;2m\xE2\x96\x84\x1b[38;2;126;104;79;48;2;59;68;57m\xE2\x96\x84\x1b[38;2;138;174;160;48;2;99;148;139m\xE2\x96\x84\x1b[38;2;35;51;41;48;2;45;77;63m\xE2\x96\x84\x1b[38;2;36;33;16;48;2;31;27;12m\xE2\x96\x84\x1b[48;2;5;1;0m \x1b[38;2;1;0;0;48;2;0;1;1m\xE2\x96\x84\x1b[38;2;2;0;0;48;2;3;0;0m\xE2\x96\x84\x1b[38;2;11;0;4;48;2;28;2;6m\xE2\x96\x84\x1b[38;2;67;35;26;48;2;68;31;36m\xE2\x96\x84\x1b[38;2;94;47;40;48;2;124;63;56m\xE2\x96\x84\x1b[38;2;150;90;69;48;2;196;123;108m\xE2\x96\x84\x1b[38;2;168;116;88;48;2;204;143;96m\xE2\x96\x84\x1b[38;2;161;117;93;48;2;216;156;119m\xE2\x96\x84\x1b[38;2;181;132;99;48;2;207;148;106m\xE2\x96\x84\x1b[38;2;141;99;84;48;2;145;84;74m\xE2\x96\x84\x1b[38;2;100;56;55;48;2;66;28;28m\xE2\x96\x84\x1b[38;2;51;26;25;48;2;140;90;85m\xE2\x96\x84\x1b[38;2;40;16;23;48;2;142;83;78m\xE2\x96\x84\x1b[38;2;41;22;19;48;2;120;65;66m\xE2\x96\x84\x1b[38;2;57;25;32;48;2;89;57;54m\xE2\x96\x84\x1b[38;2;66;29;34;48;2;150;106;89m\xE2\x96\x84\x1b[38;2;92;78;63;48;2;174;126;103m\xE2\x96\x84\x1b[38;2;11;0;0;48;2;175;134;115m\xE2\x96\x84\x1b[38;2;23;2;1;48;2;46;29;27m\xE2\x96\x84\x1b[38;2;31;4;8;48;2;38;22;28m\xE2\x96\x84\x1b[38;2;100;66;61;48;2;72;40;30m\xE2\x96\x84\x1b[38;2;47;11;14;48;2;105;54;46m\xE2\x96\x84\x1b[38;2;36;9;8;48;2;65;23;30m\xE2\x96\x84\x1b[38;2;13;1;1;48;2;36;11;7m\xE2\x96\x84\x1b[38;2;3;0;0;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;0;0;0;48;2;1;1;3m\xE2\x96\x84\x1b[38;2;7;0;0;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;7;0;0;48;2;5;2;0m\xE2\x96\x84\x1b[38;2;6;3;0;48;2;6;0;2m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;4;2;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;90;101;93;48;2;5;2;0m\xE2\x96\x84\x1b[38;2;147;150;143;48;2;8;0;1m\xE2\x96\x84\x1b[38;2;7;1;1;48;2;18;0;2m\xE2\x96\x84\x1b[38;2;4;2;1;48;2;15;7;3m\xE2\x96\x84\x1b[38;2;8;1;0;48;2;6;1;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;5;0;0m\xE2\x96\x84\x1b[38;2;7;1;0;48;2;5;2;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;5;1;1;48;2;5;2;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;3;1;0m\xE2\x96\x84\x1b[38;2;8;1;0;48;2;1;2;0m\xE2\x96\x84\x1b[38;2;17;0;1;48;2;31;34;19m\xE2\x96\x84\x1b[38;2;67;140;138;48;2;24;31;24m\xE2\x96\x84\x1b[38;2;102;174;177;48;2;127;133;111m\xE2\x96\x84\x1b[38;2;28;31;31;48;2;104;64;32m\xE2\x96\x84\x1b[38;2;9;7;11;48;2;53;78;71m\xE2\x96\x84\x1b[38;2;35;60;47;48;2;37;49;42m\xE2\x96\x84\x1b[38;2;58;77;73;48;2;28;21;11m\xE2\x96\x84\x1b[38;2;28;26;14;48;2;4;0;0m\xE2\x96\x84\x1b[48;2;1;0;0m \x1b[38;2;0;0;0;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;0;0;0;48;2;0;1;0m\xE2\x96\x84\x1b[38;2;16;1;1;48;2;33;4;9m\xE2\x96\x84\x1b[38;2;20;1;0;48;2;65;28;30m\xE2\x96\x84\x1b[38;2;39;11;10;48;2;115;70;56m\xE2\x96\x84\x1b[38;2;6;0;2;48;2;63;47;48m\xE2\x96\x84\x1b[38;2;16;1;0;48;2;86;62;57m\xE2\x96\x84\x1b[38;2;21;2;4;48;2;43;20;32m\xE2\x96\x84\x1b[38;2;34;3;18;48;2;55;28;40m\xE2\x96\x84\x1b[38;2;9;0;0;48;2;31;4;15m\xE2\x96\x84\x1b[38;2;27;5;8;48;2;23;10;13m\xE2\x96\x84\x1b[38;2;34;8;9;48;2;20;2;0m\xE2\x96\x84\x1b[38;2;69;27;32;48;2;24;9;9m\xE2\x96\x84\x1b[38;2;116;66;75;48;2;19;3;1m\xE2\x96\x84\x1b[38;2;39;4;10;48;2;25;9;8m\xE2\x96\x84\x1b[38;2;72;21;32;48;2;14;2;2m\xE2\x96\x84\x1b[38;2;127;65;57;48;2;29;9;6m\xE2\x96\x84\x1b[38;2;150;95;72;48;2;127;72;66m\xE2\x96\x84\x1b[38;2;144;89;67;48;2;101;68;48m\xE2\x96\x84\x1b[38;2;62;27;24;48;2;117;65;69m\xE2\x96\x84\x1b[38;2;22;3;3;48;2;31;7;14m\xE2\x96\x84\x1b[38;2;32;9;4;48;2;26;9;10m\xE2\x96\x84\x1b[38;2;15;1;1;48;2;10;0;0m\xE2\x96\x84\x1b[38;2;2;0;0;48;2;6;1;0m\xE2\x96\x84\x1b[38;2;4;0;0;48;2;2;0;0m\xE2\x96\x84\x1b[38;2;6;0;0;48;2;5;1;0m\xE2\x96\x84\x1b[38;2;6;2;0;48;2;4;2;0m\xE2\x96\x84\x1b[38;2;6;0;0;48;2;6;1;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;5;1;0m\xE2\x96\x84\x1b[38;2;5;2;1;48;2;7;2;0m\xE2\x96\x84\x1b[38;2;8;0;0;48;2;12;1;1m\xE2\x96\x84\x1b[38;2;4;1;0;48;2;10;0;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;4;0;0m\xE2\x96\x84\x1b[48;2;6;1;0m \x1b[38;2;5;1;2;48;2;6;1;0m\xE2\x96\x84\x1b[38;2;6;2;0;48;2;6;1;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;6;0;1;48;2;7;1;1m\xE2\x96\x84\x1b[38;2;7;1;1;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;6;0;0;48;2;7;0;0m\xE2\x96\x84\x1b[38;2;5;2;0;48;2;10;0;0m\xE2\x96\x84\x1b[38;2;6;0;0;48;2;5;2;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;4;0;0;48;2;51;67;56m\xE2\x96\x84\x1b[38;2;12;9;17;48;2;40;25;18m\xE2\x96\x84\x1b[38;2;26;27;21;48;2;42;60;45m\xE2\x96\x84\x1b[38;2;18;3;0;48;2;25;40;30m\xE2\x96\x84\x1b[38;2;21;27;14;48;2;12;3;9m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;4;6;2m\xE2\x96\x84\x1b[38;2;0;0;0;48;2;2;0;1m\xE2\x96\x84\x1b[38;2;1;2;0;48;2;2;0;0m\xE2\x96\x84\x1b[38;2;0;0;0;48;2;1;1;1m\xE2\x96\x84\x1b[38;2;0;0;1;48;2;0;0;0m\xE2\x96\x84\x1b[38;2;15;1;4;48;2;4;1;1m\xE2\x96\x84\x1b[38;2;1;1;0;48;2;29;15;13m\xE2\x96\x84\x1b[38;2;65;24;31;48;2;57;26;23m\xE2\x96\x84\x1b[38;2;85;42;31;48;2;74;30;37m\xE2\x96\x84\x1b[38;2;102;55;49;48;2;66;21;30m\xE2\x96\x84\x1b[38;2;126;55;64;48;2;41;2;7m\xE2\x96\x84\x1b[38;2;186;61;82;48;2;25;0;4m\xE2\x96\x84\x1b[38;2;208;125;132;48;2;57;8;13m\xE2\x96\x84\x1b[38;2;188;94;113;48;2;57;6;12m\xE2\x96\x84\x1b[38;2;208;123;140;48;2;45;4;16m\xE2\x96\x84\x1b[38;2;180;83;103;48;2;151;67;82m\xE2\x96\x84\x1b[38;2;57;12;22;48;2;146;63;79m\xE2\x96\x84\x1b[38;2;85;45;45;48;2;121;54;54m\xE2\x96\x84\x1b[38;2;137;80;67;48;2;129;81;65m\xE2\x96\x84\x1b[38;2;143;75;71;48;2;132;70;65m\xE2\x96\x84\x1b[38;2;65;32;33;48;2;122;75;65m\xE2\x96\x84\x1b[38;2;21;1;1;48;2;39;5;3m\xE2\x96\x84\x1b[38;2;28;5;1;48;2;21;1;2m\xE2\x96\x84\x1b[38;2;22;1;3;48;2;43;12;15m\xE2\x96\x84\x1b[38;2;6;1;1;48;2;7;0;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;7;2;0m\xE2\x96\x84\x1b[38;2;6;1;0;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;6;0;0;48;2;7;2;0m\xE2\x96\x84\x1b[38;2;3;3;0;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;8;0;1;48;2;6;1;1m\xE2\x96\x84\x1b[38;2;8;2;0;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;13;2;0;48;2;9;0;1m\xE2\x96\x84\x1b[38;2;48;39;26;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;12;1;0;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;8;0;0;48;2;6;3;0m\xE2\x96\x84\x1b[38;2;5;2;1;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;5;0;0;48;2;7;2;0m\xE2\x96\x84\x1b[38;2;5;2;1;48;2;8;1;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;5;1;1;48;2;7;3;1m\xE2\x96\x84\x1b[38;2;6;2;1;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;5;1;1;48;2;6;3;0m\xE2\x96\x84\x1b[38;2;4;1;0;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;6;0;1;48;2;7;2;0m\xE2\x96\x84\x1b[38;2;6;2;1;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;7;2;2;48;2;5;2;1m\xE2\x96\x84\x1b[38;2;4;2;0;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;5;1;1;48;2;6;3;0m\xE2\x96\x84\x1b[38;2;5;3;1;48;2;9;0;0m\xE2\x96\x84\x1b[38;2;6;1;2;48;2;7;3;2m\xE2\x96\x84\x1b[38;2;5;3;1;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;5;0;1;48;2;2;2;2m\xE2\x96\x84\x1b[38;2;2;3;1;48;2;2;0;1m\xE2\x96\x84\x1b[38;2;1;0;0;48;2;2;1;2m\xE2\x96\x84\x1b[38;2;2;0;0;48;2;1;0;0m\xE2\x96\x84\x1b[38;2;2;0;1;48;2;15;0;0m\xE2\x96\x84\x1b[38;2;23;3;0;48;2;10;0;3m\xE2\x96\x84\x1b[38;2;7;0;0;48;2;50;17;23m\xE2\x96\x84\x1b[38;2;95;52;50;48;2;99;48;58m\xE2\x96\x84\x1b[38;2;142;84;77;48;2;59;24;25m\xE2\x96\x84\x1b[38;2;129;66;49;48;2;45;14;27m\xE2\x96\x84\x1b[38;2;70;22;28;48;2;74;24;28m\xE2\x96\x84\x1b[38;2;11;2;2;48;2;109;37;49m\xE2\x96\x84\x1b[38;2;1;0;0;48;2;58;13;17m\xE2\x96\x84\x1b[38;2;7;3;1;48;2;15;8;3m\xE2\x96\x84\x1b[38;2;56;32;30;48;2;8;3;5m\xE2\x96\x84\x1b[38;2;144;90;76;48;2;43;12;19m\xE2\x96\x84\x1b[38;2;177;105;92;48;2;142;81;73m\xE2\x96\x84\x1b[38;2;143;80;63;48;2;155;88;77m\xE2\x96\x84\x1b[38;2;74;36;40;48;2;143;83;67m\xE2\x96\x84\x1b[38;2;22;13;3;48;2;22;6;3m\xE2\x96\x84\x1b[38;2;37;9;8;48;2;24;5;5m\xE2\x96\x84\x1b[38;2;10;0;3;48;2;43;13;10m\xE2\x96\x84\x1b[38;2;15;0;1;48;2;16;0;1m\xE2\x96\x84\x1b[38;2;6;2;1;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;6;2;1;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;6;3;1;48;2;11;0;7m\xE2\x96\x84\x1b[38;2;8;0;0;48;2;15;3;6m\xE2\x96\x84\x1b[38;2;8;3;1;48;2;9;0;0m\xE2\x96\x84\x1b[38;2;8;13;6;48;2;8;2;1m\xE2\x96\x84\x1b[38;2;24;18;10;48;2;9;0;0m\xE2\x96\x84\x1b[38;2;9;0;0;48;2;14;1;3m\xE2\x96\x84\x1b[38;2;17;1;1;48;2;34;22;9m\xE2\x96\x84\x1b[38;2;4;1;1;48;2;80;89;78m\xE2\x96\x84\x1b[38;2;7;2;0;48;2;5;4;0m\xE2\x96\x84\x1b[48;2;7;1;2m \x1b[38;2;5;2;0;48;2;7;1;0m\xE2\x96\x84\x1b[38;2;5;1;1;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;5;3;1;48;2;8;1;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;6;2;3;48;2;7;3;1m\xE2\x96\x84\x1b[38;2;7;2;1;48;2;9;1;0m\xE2\x96\x84\x1b[38;2;5;0;0;48;2;8;4;2m\xE2\x96\x84\x1b[38;2;2;5;1;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;8;0;1;48;2;6;4;0m\xE2\x96\x84\x1b[38;2;13;13;5;48;2;13;1;8m\xE2\x96\x84\x1b[38;2;16;32;21;48;2;10;2;0m\xE2\x96\x84\x1b[38;2;24;26;16;48;2;8;2;0m\xE2\x96\x84\x1b[38;2;6;9;3;48;2;8;3;2m\xE2\x96\x84\x1b[38;2;99;105;91;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;6;3;1m\xE2\x96\x84\x1b[38;2;38;22;15;48;2;8;2;0m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;9;3;2m\xE2\x96\x84\x1b[38;2;8;4;1;48;2;9;1;0m\xE2\x96\x84\x1b[38;2;5;1;0;48;2;4;3;1m\xE2\x96\x84\x1b[38;2;3;2;2;48;2;2;0;0m\xE2\x96\x84\x1b[38;2;2;0;1;48;2;2;3;2m\xE2\x96\x84\x1b[38;2;6;3;1;48;2;9;0;3m\xE2\x96\x84\x1b[38;2;28;2;5;48;2;23;4;6m\xE2\x96\x84\x1b[38;2;12;3;6;48;2;14;0;0m\xE2\x96\x84\x1b[38;2;71;38;37;48;2;117;63;57m\xE2\x96\x84\x1b[38;2;134;90;80;48;2;153;94;82m\xE2\x96\x84\x1b[38;2;89;60;44;48;2;177;93;83m\xE2\x96\x84\x1b[38;2;114;71;61;48;2;138;84;93m\xE2\x96\x84\x1b[38;2;81;39;35;48;2;61;32;28m\xE2\x96\x84\x1b[38;2;84;41;39;48;2;72;34;35m\xE2\x96\x84\x1b[38;2;97;48;51;48;2;145;93;81m\xE2\x96\x84\x1b[38;2;54;22;25;48;2;197;142;114m\xE2\x96\x84\x1b[38;2;85;53;46;48;2;161;105;84m\xE2\x96\x84\x1b[38;2;48;23;21;48;2;113;60;53m\xE2\x96\x84\x1b[38;2;19;0;3;48;2;15;3;3m\xE2\x96\x84\x1b[38;2;67;28;28;48;2;35;6;9m\xE2\x96\x84\x1b[38;2;17;0;0;48;2;49;26;21m\xE2\x96\x84\x1b[38;2;3;3;1;48;2;1;0;1m\xE2\x96\x84\x1b[38;2;4;1;0;48;2;8;4;2m\xE2\x96\x84\x1b[38;2;4;3;2;48;2;8;0;0m\xE2\x96\x84\x1b[38;2;5;1;1;48;2;7;3;1m\xE2\x96\x84\x1b[38;2;17;21;7;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;30;41;26;48;2;15;3;3m\xE2\x96\x84\x1b[38;2;149;212;199;48;2;31;47;40m\xE2\x96\x84\x1b[38;2;98;198;185;48;2;67;135;138m\xE2\x96\x84\x1b[38;2;110;210;221;48;2;99;177;170m\xE2\x96\x84\x1b[38;2;96;192;208;48;2;18;20;16m\xE2\x96\x84\x1b[38;2;76;153;196;48;2;10;5;0m\xE2\x96\x84\x1b[38;2;8;19;27;48;2;8;2;1m\xE2\x96\x84\x1b[38;2;7;1;1;48;2;8;0;1m\xE2\x96\x84\x1b[38;2;6;0;0;48;2;6;3;1m\xE2\x96\x84\x1b[38;2;6;3;1;48;2;9;1;0m\xE2\x96\x84\x1b[38;2;6;0;1;48;2;8;3;1m\xE2\x96\x84\x1b[38;2;4;3;0;48;2;9;1;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[38;2;7;0;2;48;2;8;5;0m\xE2\x96\x84\x1b[38;2;5;4;2;48;2;8;2;0m\xE2\x96\x84\x1b[38;2;7;1;3;48;2;6;5;1m\xE2\x96\x84\x1b[38;2;2;5;0;48;2;6;2;0m\xE2\x96\x84\x1b[38;2;6;1;1;48;2;11;3;1m\xE2\x96\x84\x1b[38;2;6;3;2;48;2;10;2;0m\xE2\x96\x84\x1b[38;2;5;1;2;48;2;7;3;0m\xE2\x96\x84\x1b[38;2;3;5;0;48;2;26;16;7m\xE2\x96\x84\x1b[38;2;5;0;2;48;2;9;9;7m\xE2\x96\x84\x1b[38;2;3;4;1;48;2;8;13;4m\xE2\x96\x84\x1b[38;2;6;1;5;48;2;16;5;4m\xE2\x96\x84\x1b[38;2;8;4;3;48;2;32;19;15m\xE2\x96\x84\x1b[38;2;5;1;2;48;2;17;9;4m\xE2\x96\x84\x1b[38;2;5;4;2;48;2;180;156;143m\xE2\x96\x84\x1b[38;2;6;2;3;48;2;25;33;13m\xE2\x96\x84\x1b[38;2;1;6;2;48;2;3;0;0m\xE2\x96\x84\x1b[38;2;4;0;0;48;2;0;5;4m\xE2\x96\x84\x1b[38;2;4;0;0;48;2;4;0;1m\xE2\x96\x84\x1b[38;2;3;0;0;48;2;22;1;3m\xE2\x96\x84\x1b[38;2;4;0;0;48;2;32;5;7m\xE2\x96\x84\x1b[38;2;12;2;0;48;2;12;6;4m\xE2\x96\x84\x1b[38;2;22;1;2;48;2;25;11;8m\xE2\x96\x84\x1b[38;2;7;0;0;48;2;18;3;8m\xE2\x96\x84\x1b[38;2;3;4;5;48;2;30;9;5m\xE2\x96\x84\x1b[38;2;12;2;2;48;2;53;23;27m\xE2\x96\x84\x1b[38;2;10;0;0;48;2;28;19;10m\xE2\x96\x84\x1b[38;2;7;0;0;48;2;39;15;14m\xE2\x96\x84\x1b[38;2;2;4;1;48;2;18;2;3m\xE2\x96\x84\x1b[38;2;27;2;4;48;2;18;5;6m\xE2\x96\x84\x1b[38;2;38;4;7;48;2;10;1;5m\xE2\x96\x84\x1b[38;2;38;9;13;48;2;47;17;15m\xE2\x96\x84\x1b[38;2;4;0;1;48;2;36;8;8m\xE2\x96\x84\x1b[38;2;2;0;1;48;2;2;4;3m\xE2\x96\x84\x1b[38;2;1;6;0;48;2;1;1;0m\xE2\x96\x84\x1b[38;2;5;0;0;48;2;2;6;2m\xE2\x96\x84\x1b[38;2;5;3;2;48;2;11;0;0m\xE2\x96\x84\x1b[38;2;9;1;0;48;2;15;5;5m\xE2\x96\x84\x1b[38;2;91;168;167;48;2;57;89;70m\xE2\x96\x84\x1b[38;2;89;175;168;48;2;174;191;168m\xE2\x96\x84\x1b[38;2;73;142;143;48;2;89;180;194m\xE2\x96\x84\x1b[38;2;18;37;36;48;2;84;162;187m\xE2\x96\x84\x1b[38;2;23;42;54;48;2;112;204;210m\xE2\x96\x84\x1b[38;2;88;177;188;48;2;89;188;205m\xE2\x96\x84\x1b[38;2;94;188;207;48;2;107;214;223m\xE2\x96\x84\x1b[38;2;94;190;202;48;2;95;187;199m\xE2\x96\x84\x1b[38;2;33;64;65;48;2;10;13;1m\xE2\x96\x84\x1b[38;2;12;19;0;48;2;8;4;2m\xE2\x96\x84\x1b[38;2;20;11;3;48;2;8;1;0m\xE2\x96\x84\x1b[38;2;5;0;1;48;2;9;4;1m\xE2\x96\x84\x1b[38;2;13;5;2;48;2;10;1;0m\xE2\x96\x84\x1b[m\n"
        "\x1b[49;38;2;7;5;1m\xE2\x96\x80\x1b[49;38;2;11;0;0m\xE2\x96\x80\x1b[49;38;2;9;5;1m\xE2\x96\x80\x1b[49;38;2;11;1;1m\xE2\x96\x80\x1b[49;38;2;9;6;0m\xE2\x96\x80\x1b[49;38;2;9;1;0m\xE2\x96\x80\x1b[49;38;2;9;5;1m\xE2\x96\x80\x1b[49;38;2;10;1;0m\xE2\x96\x80\x1b[49;38;2;9;4;1m\xE2\x96\x80\x1b[49;38;2;10;1;0m\xE2\x96\x80\x1b[49;38;2;9;5;2m\xE2\x96\x80\x1b[49;38;2;9;1;0m\xE2\x96\x80\x1b[49;38;2;6;5;2m\xE2\x96\x80\x1b[49;38;2;9;1;0m\xE2\x96\x80\x1b[49;38;2;6;5;1m\xE2\x96\x80\x1b[49;38;2;9;0;0m\xE2\x96\x80\x1b[49;38;2;5;6;1m\xE2\x96\x80\x1b[49;38;2;4;0;1m\xE2\x96\x80\x1b[49;38;2;3;4;4m\xE2\x96\x80\x1b[49;38;2;2;2;2m\xE2\x96\x80\x1b[49;38;2;2;5;4m\xE2\x96\x80\x1b[49;38;2;9;0;1m\xE2\x96\x80\x1b[49;38;2;25;0;6m\xE2\x96\x80\x1b[49;38;2;16;0;3m\xE2\x96\x80\x1b[49;38;2;13;4;4m\xE2\x96\x80\x1b[49;38;2;15;0;1m\xE2\x96\x80\x1b[49;38;2;11;5;5m\xE2\x96\x80\x1b[49;38;2;21;2;3m\xE2\x96\x80\x1b[49;38;2;21;3;4m\xE2\x96\x80\x1b[49;38;2;18;0;2m\xE2\x96\x80\x1b[49;38;2;3;4;2m\xE2\x96\x80\x1b[49;38;2;2;0;0m\xE2\x96\x80\x1b[49;38;2;5;5;2m\xE2\x96\x80\x1b[49;38;2;4;0;0m\xE2\x96\x80\x1b[49;38;2;6;5;3m\xE2\x96\x80\x1b[49;38;2;10;1;0m\xE2\x96\x80\x1b[49;38;2;17;15;10m\xE2\x96\x80\x1b[49;38;2;11;12;7m\xE2\x96\x80\x1b[49;38;2;11;22;41m\xE2\x96\x80\x1b[49;38;2;49;103;104m\xE2\x96\x80\x1b[49;38;2;9;23;15m\xE2\x96\x80\x1b[49;38;2;17;21;25m\xE2\x96\x80\x1b[49;38;2;79;151;146m\xE2\x96\x80\x1b[49;38;2;119;229;223m\xE2\x96\x80\x1b[49;38;2;71;143;173m\xE2\x96\x80\x1b[49;38;2;22;37;30m\xE2\x96\x80\x1b[49;38;2;17;6;5m\xE2\x96\x80\x1b[49;38;2;17;3;2m\xE2\x96\x80\x1b[49;38;2;9;4;2m\xE2\x96\x80\x1b[49;38;2;10;0;0m\xE2\x96\x80\x1b[m\n"
    );
}
