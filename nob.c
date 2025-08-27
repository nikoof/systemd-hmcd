#define NOB_IMPLEMENTATION
#define NOB_EXPERIMENTAL_DELETE_OLD
#include "nob.h"

#define FLAG_IMPLEMENTATION
#include "flag.h"

#define BUILD_DIR "build/"
#define OUT_NAME "hmc"

void fusage(FILE *stream, const char* progname) {
  fprintf(stream, "usage: %s [OPTIONS]\n", progname);
  fprintf(stream, "OPTIONS:\n");
  flag_print_options(stream);
}

int main(int argc, char **argv) {
  NOB_GO_REBUILD_URSELF(argc, argv);

  bool *help = flag_bool("help", false, "Print this message and exit.");
  bool *debug = flag_bool("debug", false, "Debug build.");
  bool *run = flag_bool("run", false, "Run final binary after build.");

  if (!flag_parse(argc, argv)) {
    fusage(stderr, argv[0]);
    flag_print_error(stderr);
    return 1;
  }

  if (*help) {
    fusage(stdout, argv[0]);
    return 0;
  }

  if (!nob_mkdir_if_not_exists(BUILD_DIR)) return 1;

  Nob_Cmd cmd = {0};
  nob_cc(&cmd);
  nob_cmd_append(&cmd, "-Wall", "-Wextra");

  if (*debug) nob_cmd_append(&cmd, "-Og", "-ggdb3");
  else        nob_cmd_append(&cmd, "-O2");

  nob_cmd_append(&cmd, "-o", BUILD_DIR OUT_NAME);
  nob_cmd_append(&cmd, "hmc.c");
  nob_cmd_append(&cmd, "-lgpgme");

  if (!nob_cmd_run(&cmd)) return 1;

  if (*run) {
    nob_cmd_append(&cmd, BUILD_DIR OUT_NAME);
    if (!nob_cmd_run(&cmd)) return 1;
  }

  return 0;
}
