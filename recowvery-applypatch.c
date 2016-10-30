#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define APP_NAME "recowvery-applypatch"

/* this is where we need to work on the decompressed cpio */
#define WORK_DIR      "/cache"

/* msm8996 */
#define BLOCK_BOOT     "/dev/block/bootdevice/by-name/boot"
#define BLOCK_RECOVERY "/dev/block/bootdevice/by-name/recovery"

/* universal8890 */
//#define BLOCK_BOOT     "/dev/block/platform/155a0000.ufs/by-name/BOOT"
//#define BLOCK_RECOVERY "/dev/block/platform/155a0000.ufs/by-name/RECOVERY"

/* name of the init file we're going to overwrite */
static const char *init_rc = "init.lge.fm.rc";
static const char *init_rc_content =
/* this is the content of our new init file */
"on boot\n"
"    setprop ro.fm.module BCM\n"
"    setenforce 0\n"
"    write /sys/fs/selinux/enforce 0\n"
"\n"
"on property:sys.boot_completed=1\n"
"    setenforce 0\n"
"    write /sys/fs/selinux/enforce 0\n";
/* end of init file content */

// keep our common utility functions in another file
#include "recowvery-utils.c"

static int flash_permissive_boot(void)
{
	int ret = 0;
	uint32_t sz;
	boot_img image;
	const char *ramdisk = WORK_DIR "/ramdisk.gz";
	const char *cpio = WORK_DIR "/ramdisk.cpio";

	LOGV("------------");
/* start read boot image */

	LOGV("Loading boot image from block device '%s'...", BLOCK_BOOT);
	ret = load_boot_image(&image, BLOCK_BOOT);
	if (ret) {
		LOGE("Failed to load boot image: %s", strerror(ret));
		goto oops;
	}
	LOGV("Loaded boot image!");

/* end read boot image */
	LOGV("------------");
/* start ramdisk modification */

	LOGV("Saving old ramdisk to file");
	ret = write_binary_to_file(ramdisk, image.ramdisk, image.hdr.ramdisk_size);
	if (ret)
		goto oops;

	ret = decompress_ramdisk(ramdisk, cpio);
	if (ret)
		goto oops;

	LOGV("------------");
/* start add modified init.lge.fm.rc to ramdisk cpio */

	byte* cpiodata = cpio_file(init_rc, (byte*)init_rc_content, strlen(init_rc_content), &sz);

	ret = cpio_append(cpio, cpiodata, sz);
	if (ret) {
		LOGE("Failed to append '%s' to the cpio file", init_rc);
		goto oops;
	}

/* end add modified init.lge.fm.rc to ramdisk cpio */
	LOGV("------------");

	ret = compress_ramdisk(cpio, ramdisk);
	if (ret)
		goto oops;

	LOGV("Loading new ramdisk into boot image");
	ret = bootimg_load_ramdisk(&image, ramdisk);
	if (ret)
		goto oops;

/* end ramdisk modification */
	LOGV("------------");
/* start cmdline set */

	LOGV("Current cmdline: \"%s\"", image.hdr.cmdline);
	LOGV("Setting permissive command line");
	bootimg_set_cmdline_arg(&image, "androidboot.selinux", "permissive");
	bootimg_set_cmdline_arg(&image, "enforcing", "0");
	LOGV("New cmdline: \"%s\"", image.hdr.cmdline);

/* end cmdline set */
	LOGV("------------");
/* start flash recovery */

	LOGV("Writing modified boot image to block device '%s'...", BLOCK_RECOVERY);
	ret = write_boot_image(&image, BLOCK_RECOVERY);
	if (ret) {
		LOGE("Failed to write boot image: %s", strerror(ret));
		goto oops;
	}
	LOGV("Done!");

/* end flash recovery */
	LOGV("------------");

	LOGV("Permissive boot has been has been flashed to recovery successfully!")
	LOGV("You may use 'reboot recovery' now to enter a permissive system.");
	LOGV("***********************************************");
	LOGV("*       give jcadduono a hug, will ya?        *");
	LOGV("***********************************************");

	ret = 0;
oops:
	free_boot_image(&image);
	return ret;
}

int main(void)
{
	int ret = 0;

	LOGV("Welcome to %s!", APP_NAME);

	ret = flash_permissive_boot();
	if (ret)
		goto oops;

	return 0;
oops:
	LOGE("Failed! Exiting...");
	return ret;
}
