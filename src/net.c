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

uint8_t hmc_net_serve(uint16_t port) {
  int32_t fd;
  /// TODO: Support ipv6
  ENEG((fd = socket(AF_INET, SOCK_STREAM, 0)), "Could not create listening socket! %m");

  int opt = 1;
  ENEG(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)), "Could not set socket options! %m");

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  ENEG(bind(fd, (struct sockaddr*)&addr, sizeof(addr)), "Could not bind socket to port %u! %m", port);
  nob_log(NOB_INFO, "systemd_hmcd: Started listening on port %hu", port);
  ENEG(listen(fd, 1), "Could not set up socket to listen! %m");
  int32_t remote_fd;
  socklen_t addrl = sizeof(addr);
  ENEG((remote_fd = accept(fd, (struct sockaddr*)&addr, &addrl)), "Could not accept connection from remote! %m");
  
  ssize_t readlen;
  char buffer[1024] = { 0 };
  ENEG((readlen = read(remote_fd, buffer, NOB_ARRAY_LEN(buffer))), "Could not read from remote socket! %m");
  printf("%s\n", buffer);

  close(remote_fd);
  close(fd);

  return 0;
}

uint8_t hmc_net_connect(char *ip, uint16_t port) {
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
  ENEG(send(fd, belestemuia, strlen(belestemuia), 0), "Could not send to remote server! %m");
  close(fd);
  return 0;
}
