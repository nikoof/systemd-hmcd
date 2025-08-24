#ifndef UTIL_H
#define UTIL_H

#include "../nob.h"

#define _EE(op, targ, cmd, res, args...) {if ((cmd) op (targ)) { nob_log(NOB_ERROR, "systemd_hmcd: " res "!\n", ##args); } return 1;}
#define EZERO(cmd, res, args...) _EE(==,    0, cmd, res, args)
#define ENULL(cmd, res, args...) _EE(==, NULL, cmd, res, args)
#define ENEZ (cmd, res, args...) _EE(!=,    0, cmd, res, args)
#define ENEG (cmd, res, args...) _EE(< ,    0, cmd, res, args)

#define GERR(cmd, fmt, args...) \
  { gpgme_error_t err; if ((err = cmd) != 0) { nob_log(NOB_ERROR, "systemd_hmcd: " fmt " (%s)\n", ##args, gpgme_strerror(err)); } }

#endif
