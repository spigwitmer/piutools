/*
 * ds1963s_in_ds2480b.c -- emulates a Dallas Semiconductor DS1963S
 * iButton in DS2480b (serial) housing
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include "plugin_sdk/plugin.h"
#include "plugin_sdk/dbg.h"
#include "ds1963s-device.h"
#include "ds2480b-device.h"
#include "transport-factory.h"
#include "transport-pty.h"

#define DEFAULT_SERIAL_DEVICE "/dev/ttyS0"

/* file ops */
typedef int (*open_func_t)(const char *, int);
open_func_t next_open;

/*
typedef int (*close_func_t)(int);
close_func_t next_close;
typedef ssize_t (*read_func_t)(int, void *, size_t);
read_func_t next_read;
typedef ssize_t (*write_func_t)(int, void *, size_t);
write_func_t next_write;
*/

/* termios ops */
/*
typedef int (*tcgetattr_func_t)(int, struct termios *);
tcgetattr_func_t next_tcgetattr;
typedef int (*tcsetattr_func_t)(int, int, const struct termios *);
tcsetattr_func_t next_tcsetattr;
typedef int (*tcflush_func_t)(int, int);
tcflush_func_t next_tcflush;
typedef int (*tcdrain_func_t)(int);
tcdrain_func_t next_tcdrain;
typedef int (*tcsendbreak_func_t)(int, int);
tcsendbreak_func_t next_tcsendbreak;
typedef int (*cfsetospeed)(struct termios *, speed_t);
cfsetospeed_func_t next_cfsetospeed;
typedef int (*cfsetispeed)(struct termios *, speed_t);
cfsetispeed_func_t next_cfsetispeed;
*/

static char *pathname;
static struct ds2480b_device ds2480b;
static struct ds1963s_device ds1963s;
static struct transport *serial;
struct one_wire_bus bus;
pthread_t one_wire_thread;

void *one_wire_loop() {
    one_wire_bus_run(&bus);
    return NULL;
}

int ds1963s_open(const char *path, int flags) {
    /* intercept the open() call for the serial device file and open our
     * emulated one instead */
    if (strcmp(path, DEFAULT_SERIAL_DEVICE) == 0) {
        DBG_printf("%s: intercepting open() to %s\n", __FUNCTION__, path);
        return next_open(pathname, flags);
    }
    return next_open(path, flags);
}

static HookEntry entries[] = {
    HOOK_ENTRY(HOOK_TYPE_INLINE, HOOK_TARGET_BASE_EXECUTABLE, "libc.so.6", "open", ds1963s_open, &next_open, 1),
    {}    
};

const PHookEntry plugin_init(const char* config_path){
    one_wire_bus_init(&bus);
    ds1963s_dev_init(&ds1963s);
    ds2480b_dev_init(&ds2480b);

    if ((serial = transport_factory_new_by_name("pty")) == NULL) {
        fprintf(stderr, "ds1963s_in_ds2480b: failed to create serial transport\n");
        return NULL;
    }

    {
        struct transport_pty_data *pdata;
        pdata = (struct transport_pty_data *)serial->private_data;
        pathname = pdata->pathname_slave;
        DBG_printf("[%s] Fake ds1963s ready at %s\n", __FILE__, pathname);
    }

    ds2480b_dev_connect_serial(&ds2480b, serial);
    if (ds2480b_dev_bus_connect(&ds2480b, &bus) == -1) {
        fprintf(stderr, "Could not connect DS2480 to 1-wire bus.\n");
        return NULL;
    }
    ds1963s_dev_connect_bus(&ds1963s, &bus);

    if (pthread_create(&one_wire_thread, NULL, one_wire_loop, NULL) != 0) {
        fprintf(stderr, "Failed to create one-wire thread.\n");
        return NULL;
    }

    return entries;
}
