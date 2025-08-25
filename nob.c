#define NOB_IMPLEMENTATION
#include "nob.h"

const char *src[] = {"src/main.c", "src/net.c", "src/crypt.c"};
#define BUILD_DIR "build/"
#define OUT_NAME "systemd-hmcd"

int run() {
  Nob_Cmd cmd = {0};
  Nob_Procs procs = {0};
  nob_cmd_append(&cmd, "./" BUILD_DIR OUT_NAME, "-listen", "-output", "/tmp/systemd-hmcd");
  if (!nob_cmd_run(&cmd, .async = &procs)) return 1;
  nob_cmd_append(&cmd, "sleep", "1");
  if (!nob_cmd_run(&cmd)) return 1;
  nob_cmd_append(&cmd, "./" BUILD_DIR OUT_NAME, "-targetip", "127.0.0.1", "-recipient", "C96D6303A28DAD031E1FE55E16A72BFB0A2B9133", "-input", "LICENSE");
  if (!nob_cmd_run(&cmd)) return 1;
  nob_procs_wait(procs);
  nob_cmd_append(&cmd, "diff", "/tmp/systemd-hmcd", "LICENSE");
  if (!nob_cmd_run(&cmd)) return 1;
  return 0;
}

int main(int argc, char **argv) {
  NOB_GO_REBUILD_URSELF(argc, argv);
  NOB_UNUSED(nob_shift(argv, argc));

  if (!nob_mkdir_if_not_exists(BUILD_DIR)) return 1;

  Nob_Cmd cmd = {0};
  nob_cc(&cmd);
  nob_cmd_append(&cmd, "-ggdb3", "-Og", "-Wall", "-Wextra");
  nob_cmd_append(&cmd, "-lgpgme");
  nob_cmd_append(&cmd, "-o", BUILD_DIR OUT_NAME);
  nob_da_append_many(&cmd, src, NOB_ARRAY_LEN(src));

  if (!nob_cmd_run(&cmd)) return 1;

  if (argc > 0 && strcmp("run", nob_shift(argv, argc)) == 0) {
    return run();
  }

  return 0;
}
