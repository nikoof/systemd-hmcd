#ifndef UTIL_H
#define UTIL_H

#define _EE(op, targ, cmd, res, args...) {if ((cmd) op (targ)) { nob_log(NOB_ERROR, "systemd_hmcd: " res "!\n", ##args); } return 1;}
#define EZERO(cmd, res, args...) _EE(==,    0, cmd, res, args)
#define ENULL(cmd, res, args...) _EE(==, NULL, cmd, res, args)
#define ENEZ (cmd, res, args...) _EE(!=,    0, cmd, res, args)
#define ENEG (cmd, res, args...) _EE(< ,    0, cmd, res, args)

#endif
