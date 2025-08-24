#ifndef NET_H
#define NET_H

#include <stdint.h>

uint8_t hmc_net_serve(uint16_t port);
uint8_t hmc_net_connect(char *ip, uint16_t port);

#endif
