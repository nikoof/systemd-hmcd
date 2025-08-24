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

uint8_t hmc_net_serve(struct hmc_net_socket_serve *__restrict e, uint16_t port) {
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

  return 0;
}

uint8_t hmc_net_read(struct hmc_net_socket_serve *__restrict e) {
  ENEG((e->readl = read(e->remote_fd, e->data, e->msglen + 4)), "Could not read from remote socket! %m");
  hmc_crypt_decrypt(e->data, e->readl, e->plaintext, e->msglen);
  return 0;
}

uint8_t hmc_net_read_handshake(struct hmc_net_socket_serve *__restrict e) {
  char data[1024]; e->data = data;
  char plaintext[1024]; e->plaintext = plaintext;
  e->msglen = 512;
  ENEG(hmc_net_read(e), "Could not complete read!");

  ENEZ((plaintext[0] == 0x69 && plaintext[1] == 0x69), "Handshake did not contain the correct signature");
#define US(pos, shift) (((uint64_t)(plaintext[pos]))<<(shift))
  e->datalen = US(2, 24) | US(3, 16) | US(4, 8) | US(5, 0);
  e->msglen  = US(6, 24) | US(7, 16) | US(8, 8) | US(9, 0);
  ENEZ((e->msglen > HMC_NET_MAX_MSG_LEN), "Peer is trying to send messages bigger than the max package len, aborting! %u > %u", e->msglen, HMC_NET_MAX_MSG_LEN);
#undef US

  ENULL((e->data = malloc(get_big_size(e->msglen))), "Could not allocate buffer of size %u for reading data!", get_big_size(e->msglen));
  ENULL((e->plaintext = malloc(e->msglen + 20)), "Could not allocate buffer of size %u for plaintext data!", e->msglen + 20);
  return 0;
}

uint8_t hmc_net_close_read(struct hmc_net_socket_serve *__restrict e) {
  free(e->data);
  free(e->plaintext);
  ENEG(close(e->fd), "Could not close local fd! %m");
  ENEG(close(e->remote_fd), "Could not close remote fd! %m");
  return 0;
}

uint8_t hmc_net_connect(struct hmc_net_socket_connect *__restrict e, char *ip, uint16_t port) {
  int32_t fd;
  /// TODO: Support ipv6 with AF_INET6
  ENEG((fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create connecting socket! %m");
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  /// TODO: Support ipv6 with AF_INET6
  ENEG(inet_pton(AF_INET, ip, &serv_addr.sin_addr) - 1, "Address %s invalid or not supported! %m", ip);
  ENEG(connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)), "Could not connect to %s:%hu! %m", ip, port);

  char belestemuia[256] = "Hallo, Leute!\n";
  close(fd);
  return 0;
}

uint8_t hmc_net_send(struct hmc_net_socket_connect *__restrict e, char *__restrict buf, size_t len) {
  hmc_crypt_encrypt(e->recipient, buf, len, e->cipher, get_big_size(e->msglen));
  ENEG(send(e->fd, buf, len, 0), "Could not send to remote server! %m");
  return 0;
}

uint8_t hmc_net_send_handshake(struct hmc_net_socket_connect *__restrict e, const char *recipient, uint32_t datalen, uint32_t msglen) {
  char buf[512] = {0};
  buf[0] = 0x69;
  buf[1] = 0x69;
#define SU(data,shift) (((data)>>(shift))&0xFF)
  buf[2] = SU(datalen, 24);
  buf[3] = SU(datalen, 16);
  buf[4] = SU(datalen,  8);
  buf[5] = SU(datalen,  0);
  buf[6] = SU( msglen, 24);
  buf[7] = SU( msglen, 16);
  buf[8] = SU( msglen,  8);
  buf[9] = SU( msglen,  0);
#undef SU
  e->cipher = malloc(get_big_size(msglen));
  e->recipient = recipient;
  e->msglen = msglen;
  hmc_net_send(e, buf, 10);
}

uint8_t hmc_net_close_connect(struct hmc_net_socket_connect *__restrict e) {
  free(e->cipher);
  ENEG(close(e->fd), "Could not close local fd! %m");
}
