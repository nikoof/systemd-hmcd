#ifndef NET_H
#define NET_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../nob.h"

uint8_t hmc_serve(uint16_t port);

uint8_t hmc_connect(char *ip, uint16_t port);

#endif
