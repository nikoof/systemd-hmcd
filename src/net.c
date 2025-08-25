#include "net.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../nob.h"
#include "util.h"
#include "crypt.h" // Crypto Bro

static uint32_t get_big_size(uint32_t ss) { return ss * 4 + 60; }

void hmc_net_serve(struct hmc_net_socket_serve *__restrict e, uint16_t port) {
  /// TODO: Support ipv6
  ENEG((e->fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create listening socket! %m");

  int opt = 1;
  ENEG(setsockopt(e->fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)), "Could not set socket options! %m");

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  ENEG(bind(e->fd, (struct sockaddr*)&addr, sizeof(addr)), "Could not bind socket to port %u! %m", port);
  nob_log(NOB_INFO, "systemd_hmcd: Started listening on port %hu", port);

  ENEG(listen(e->fd, 1), "Could not set up socket to listen! %m");
  socklen_t addrl = sizeof(addr);
  ENEG((e->remote_fd = accept(e->fd, (struct sockaddr*)&addr, &addrl)), "Could not accept connection from remote! %m");
  nob_log(NOB_INFO, "systemd_hmcd: Got connection from %u", e->remote_fd);
}

size_t hmc_net_read(struct hmc_net_socket_serve *__restrict e) {
  size_t readl;
  ENEG((readl = read(e->remote_fd, e->cipher, 2)), "Could not read from remote socket! %m");
  if (readl != 2) { return 0; }
  uint32_t curmsglen = (uint32_t)((uint8_t)(e->cipher[0]) << 8) | (uint32_t)((uint8_t)e->cipher[1]); /// =
  ENEG((readl = read(e->remote_fd, e->cipher, curmsglen)), "Could not read from remote socket! %m");
  if (readl == 0) { return 0; }
  return hmc_crypt_decrypt(e->cipher, readl, e->plaintext, HMC_NET_MESSAGE_LEN);
}

void hmc_net_read_handshake(struct hmc_net_socket_serve *__restrict e) {
  char cipher[1024]; e->cipher = cipher;
  char plaintext[1024]; e->plaintext = plaintext;
  hmc_net_read(e);

  ENEZ(((plaintext[0] != 0x69) || (plaintext[1] != 0x69)), "Handshake did not contain the correct signature");
#define US(pos, shift) (((uint64_t)((uint8_t)plaintext[pos]))<<(shift))
  e->datalen = US(2, 24) | US(3, 16) | US(4, 8) | US(5, 0);
#undef US

  ENULL((e->cipher = malloc(get_big_size(HMC_NET_MESSAGE_LEN))), "Could not allocate buffer of size %u for reading data!", get_big_size(HMC_NET_MESSAGE_LEN));
  ENULL((e->plaintext = malloc(HMC_NET_MESSAGE_LEN + 20)), "Could not allocate buffer of size %u for plaintext data!", HMC_NET_MESSAGE_LEN + 20);
}

void hmc_net_close_read(struct hmc_net_socket_serve *__restrict e) {
  free(e->cipher);
  free(e->plaintext);
  ENEG(close(e->fd), "Could not close local fd! %m");
  ENEG(close(e->remote_fd), "Could not close remote fd! %m");
}

void hmc_net_connect(struct hmc_net_socket_connect *__restrict e, char *ip, uint16_t port) {
  /// TODO: Support ipv6 with AF_INET6
  ENEG((e->fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create connecting socket! %m");
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  /// TODO: Support ipv6 with AF_INET6
  ENEG(inet_pton(AF_INET, ip, &serv_addr.sin_addr) - 1, "Could not parse address %s! %s", ip, (errno == EAFNOSUPPORT) ? strerror(errno) : "Invalid address");
  ENEG(connect(e->fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)), "Could not connect to %s:%hu! %m", ip, port);
  nob_log(NOB_INFO, "Connected to remote %s:%hu!", ip, port);
}

void hmc_net_send(struct hmc_net_socket_connect *__restrict e, char *__restrict buf, size_t len) {
  size_t mlen = hmc_crypt_encrypt(e->recipient, buf, len, e->cipher, get_big_size(HMC_NET_MESSAGE_LEN));
  uint8_t mlenbuf[2] = {0}; mlenbuf[0] = ((mlen & 0xFF00) >> 8); mlenbuf[1] = (mlen & 0xFF);
  ENEG(send(e->fd, mlenbuf, 2, 0), "Could not send to remote server! %m");
  ENEG(send(e->fd, e->cipher, mlen, 0), "Could not send to remote server! %m");
}

void hmc_net_send_handshake(struct hmc_net_socket_connect *__restrict e, const char *recipient) {
  char buf[10] = {0};
  buf[0] = 0x69; buf[1] = 0x69;
#define SU(data,shift) (((data)>>(shift))&0xFF)
  buf[2] = SU(e->datalen, 24);
  buf[3] = SU(e->datalen, 16);
  buf[4] = SU(e->datalen,  8);
  buf[5] = SU(e->datalen,  0);
  buf[6] = SU(HMC_NET_MESSAGE_LEN, 24);
  buf[7] = SU(HMC_NET_MESSAGE_LEN, 16);
  buf[8] = SU(HMC_NET_MESSAGE_LEN,  8);
  buf[9] = SU(HMC_NET_MESSAGE_LEN,  0);
#undef SU
  e->cipher = malloc(get_big_size(HMC_NET_MESSAGE_LEN));
  e->recipient = recipient;
  hmc_net_send(e, buf, 10);
}

void hmc_net_close_connect(struct hmc_net_socket_connect *__restrict e) {
  free(e->cipher);
  ENEG(close(e->fd), "Could not close local fd! %m");
}
