#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <sys/types.h>

#define HMC_NET_MESSAGE_LEN 4096

struct hmc_net_socket_serve {
  int32_t fd;
  int32_t remote_fd;
  uint32_t datalen;
  char *cipher; char *plaintext; 
};

struct hmc_net_socket_connect {
  int32_t fd;
  uint32_t msglen;
  uint32_t datalen;
  char *cipher;
  const char *recipient;
};

void hmc_net_serve(struct hmc_net_socket_serve *__restrict e, uint16_t port);
size_t hmc_net_read(struct hmc_net_socket_serve *__restrict e);
void hmc_net_read_handshake(struct hmc_net_socket_serve *__restrict e);
void hmc_net_close_read(struct hmc_net_socket_serve *__restrict e);
void hmc_net_connect(struct hmc_net_socket_connect *__restrict e, char *ip, uint16_t port);
void hmc_net_send(struct hmc_net_socket_connect *__restrict e, char *__restrict buf, size_t len);
void hmc_net_send_handshake(struct hmc_net_socket_connect *__restrict e, const char *recipient);
void hmc_net_close_connect(struct hmc_net_socket_connect *__restrict e);

#endif
