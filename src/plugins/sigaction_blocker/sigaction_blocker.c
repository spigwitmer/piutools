#include <stdlib.h>
#include <unistd.h>
#include "plugin_sdk/plugin.h"
#include "plugin_sdk/dbg.h"

/* sigaction_blocker: thwarts any attempt at installing a customs signal
 * handler
 */

int sigaction_blocker_sigaction(int sig, const void *act, void *oact) {
    DBG_printf("Blocking sigaction() attempt for signal %d\n", sig);
    return 0;
}

static HookEntry entries[] = {
    HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "sigaction", sigaction_blocker_sigaction, NULL, 1),
    {}
};

const PHookEntry plugin_init(const char* config_path) {
    return entries;
}
