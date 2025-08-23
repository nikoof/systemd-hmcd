#ifndef NET_H
#define NET_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../nob.h"

uint8_t hmc_serve(uint16_t port) {

  nob_log(NOB_INFO, "Pula %u\n", port);

}

uint8_t hmc_connect(char *ip, uint16_t port) {

}


#endif
