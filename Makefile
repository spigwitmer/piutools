BUILD_ROOT := build
PLUGIN_BUILD_ROOT := $(BUILD_ROOT)/plugins

PLUGIN_INCLUDES := src/plugin_sdk/*.c -I src

# additional CFLAGS for the loader and plugins
CFLAGS ?=

ifeq ($(findstring .plugin,$(MAKECMDGOALS)),.plugin)
  $(shell mkdir -p $(PLUGIN_BUILD_ROOT))
endif

# --- Core Dependencies ---
loader:
	cc -shared -m32 $(CFLAGS) -fPIC src/piutools_loader.c $(PLUGIN_INCLUDES) -ldl -o $(BUILD_ROOT)/piutools.so

# --- Plugins ---
plugins: asound.plugin  ata_hdd.plugin microdog.plugin s3d_opengl.plugin deadlock.plugin ds1963s_in_ds2480b.plugin filesystem_redirect.plugin ticket_dispenser.plugin usbfs_null.plugin x11_keyboard_input.plugin pro1_data_zip.plugin

asound.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/asound/asound.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

ata_hdd.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/ata_hdd/ata_hdd.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

deadlock.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/deadlock/deadlock.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

DS1963S_UTILS_SOURCES := src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/1-wire-bus.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/coroutine.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/ds1963s-common.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/ds1963s-device.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/ds2480b-device.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/sha1.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/transport-factory.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/transport-pty.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/transport-unix.c \
						 src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src/transport.c

ds1963s_in_ds2480b.plugin:
	git submodule update --init --recursive # TODO: un-cheese
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/ds1963s_in_ds2480b/ds1963s_in_ds2480b.c $(DS1963S_UTILS_SOURCES) $(PLUGIN_INCLUDES) -lpthread -I src/plugins/ds1963s_in_ds2480b/ds1963s-utils/src -o $(PLUGIN_BUILD_ROOT)/$@

exec_blocker.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/exec_blocker/exec_blocker.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

PRO1_DATA_ZIP_OW_SOURCES := src/plugins/pro1_data_zip/ow/crcutil.c \
							src/plugins/pro1_data_zip/ow/ds2480ut.c \
							src/plugins/pro1_data_zip/ow/linuxlnk.c \
							src/plugins/pro1_data_zip/ow/owerr.c \
							src/plugins/pro1_data_zip/ow/owllu.c \
							src/plugins/pro1_data_zip/ow/ownetu.c \
							src/plugins/pro1_data_zip/ow/owsesu.c \
							src/plugins/pro1_data_zip/ow/owtrnu.c \
							src/plugins/pro1_data_zip/ow/sha18.c \
							src/plugins/pro1_data_zip/ow/shaib.c

pro1_data_zip.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/pro1_data_zip/*.c src/plugin_sdk/crypt/sha1.c $(PRO1_DATA_ZIP_OW_SOURCES) $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

locale.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/locale/locale.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

pit.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/pit/pit.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

io_mk5io.plugin:
	cc -shared -m32 $(CFLAGS) $(PLUGIN_INCLUDES) src/plugins/io_mk5io/*.c -o $(PLUGIN_BUILD_ROOT)/$@

eeprom.plugin:
	cc -shared -m32 $(CFLAGS) $(PLUGIN_INCLUDES) src/plugins/eeprom/*.c -o $(PLUGIN_BUILD_ROOT)/$@
	
lockchip.plugin:
	cc -shared -m32 $(CFLAGS) $(PLUGIN_INCLUDES) src/plugins/lockchip/*.c -o $(PLUGIN_BUILD_ROOT)/$@

io_mk6io.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/io_mk6io/*.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

x11_keyboard_input.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/x11_keyboard_input/*.c $(PLUGIN_INCLUDES) -lX11 -o $(PLUGIN_BUILD_ROOT)/$@

fake_libusb.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/fake_libusb/*.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

hasp.plugin:
	cc -shared -m32 $(CFLAGS) src/plugins/hasp/*.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

microdog.plugin:
	cc -shared -m32 $(CFLAGS) $(PLUGIN_INCLUDES) src/plugins/microdog/microdog/*.c -I src/plugins/microdog/microdog src/plugins/microdog/microdog.c -o $(PLUGIN_BUILD_ROOT)/$@

s3d_opengl.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/s3d_opengl/s3d_opengl.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

usbfs_null.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/usbfs_null/usbfs_null.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

stlfix.plugin:
	cc -shared -m32 $(CFLAGS) src/plugins/stlfix/*.c -I src -ldl -o $(PLUGIN_BUILD_ROOT)/$@

ticket_dispenser.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/ticket_dispenser/*.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

usb_profile.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/usb_profile/*.c src/plugins/usb_profile/nx2/*.c src/plugins/usb_profile/nxa/*.c src/plugins/usb_profile/fex/*.c src/plugins/usb_profile/fiesta/*.c src/plugins/usb_profile/fiesta2/*.c -lpthread $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@

# --- WORK IN PROGRESS ---
usbfs_emulator.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/usbfs_emulator/usbfs_emulator.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@


filesystem_redirect.plugin:
	cc -shared -m32 -fPIC $(CFLAGS) src/plugins/filesystem_redirect/filesystem_redirect.c $(PLUGIN_INCLUDES) -o $(PLUGIN_BUILD_ROOT)/$@



