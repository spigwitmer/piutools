#include <linux/reboot.h>
#include <stdlib.h>
#include <unistd.h>
#include "plugin_sdk/plugin.h"

/* reboot_blocker: thwarts a reboot attempt and just exits the program instead */

int reboot_blocker_reboot(int cmd) {
    DBG_printf("Blocking reboot() attempt\n");
    exit(0);
}

static HookEntry entries[] = {
    HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "reboot", reboot_blocker_reboot, NULL, 1),
    {}
};

const PHookEntry plugin_init(const char* config_path) {
    return entries;
}
