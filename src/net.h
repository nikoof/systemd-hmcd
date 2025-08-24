#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <sys/types.h>

#define HMC_NET_MAX_MSG_LEN (1 * 1024 * 1024 * 1024) // 1GB

struct hmc_net_socket_serve {
  int32_t fd;
  int32_t remote_fd;
  uint32_t datalen;
  uint32_t msglen;
  char *data; char *plaintext; 
  ssize_t readl;
};

struct hmc_net_socket_connect {
  int32_t fd;
  uint32_t msglen;
  char *cipher;
  const char *recipient;
};

uint8_t hmc_net_serve(struct hmc_net_socket_serve *__restrict e, uint16_t port);
uint8_t hmc_net_read(struct hmc_net_socket_serve *__restrict e);
uint8_t hmc_net_read_handshake(struct hmc_net_socket_serve *__restrict e);
uint8_t hmc_net_close_read(struct hmc_net_socket_serve *__restrict e);
uint8_t hmc_net_connect(struct hmc_net_socket_connect *__restrict e, char *ip, uint16_t port);
uint8_t hmc_net_send(struct hmc_net_socket_connect *__restrict e, char *__restrict buf, size_t len);
uint8_t hmc_net_send_handshake(struct hmc_net_socket_connect *__restrict e, const char *recipient, uint32_t datalen, uint32_t msglen);
uint8_t hmc_net_close_connect(struct hmc_net_socket_connect *__restrict e);

#endif
