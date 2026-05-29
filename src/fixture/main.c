#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct app_state state = {0};

    // Determine mode: argv[1] > $BACKSEAT_FIXTURE_MODE > default (listener).
    const char *mode_arg = NULL;
    if (argc > 1) {
        mode_arg = argv[1];
    } else {
        mode_arg = getenv("BACKSEAT_FIXTURE_MODE");
    }

    if (mode_arg && strcmp(mode_arg, "dispatcher") == 0) {
        state.mode = FIXTURE_DISPATCHER;
    } else {
        state.mode = FIXTURE_LISTENER;
    }

    setup_signals();
    allow_same_uid_ptrace();

    if (connect_and_bind(&state) != 0)
        return 1;

    return run_loop(&state);
}
