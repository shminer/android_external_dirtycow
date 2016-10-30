#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/capability.h>

#define APP_NAME "recowvery"

/* this is where we need to work on the decompressed cpio */
#define WORK_DIR      "/cache"

/* msm8996 */
#define BLOCK_BOOT     "/dev/block/bootdevice/by-name/boot"

/* universal8890 */
//#define BLOCK_BOOT     "/dev/block/platform/155a0000.ufs/by-name/BOOT"

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
/* start flash boot */

	LOGV("Writing modified boot image to block device '%s'...", BLOCK_BOOT);
	ret = write_boot_image(&image, BLOCK_BOOT);
	if (ret) {
		LOGE("Failed to write boot image: %s", strerror(ret));
		goto oops;
	}
	LOGV("Done!");

/* end flash boot */
	LOGV("------------");

	LOGV("Boot partition image has been set to permissive successfully!")
	LOGV("You may use 'reboot' now to enter a permissive system.");
	LOGV("***********************************************");
	LOGV("*    give jcadduono another hug, will ya?     *");
	LOGV("***********************************************");

	ret = 0;
oops:
	free_boot_image(&image);
	return ret;
}

enum {
	DO_NOTHING = 0,
	DO_EXEC,
	DO_SU,
	DO_FLASH
};

int main(int argc, char **argv)
{
	int ret = 0;
	int run = DO_NOTHING;
	struct __user_cap_header_struct capheader;
	struct __user_cap_data_struct capdata[2];
	int uid, i, argc_exec;
	char** argv_exec;

	LOGV("Welcome to %s! (%s)", APP_NAME, "run-as");

	if (argc < 2)
		goto uid;

	if (!strcmp(argv[1], "exec")) {
		if (argc == 2) {
			LOGV("Not enough parameters for exec!");
			goto usage;
		}
		run = DO_EXEC;
	} else
	if (!strcmp(argv[1], "su")) {
		run = DO_SU;
	} else
	if (!strcmp(argv[1], "flash")) {
		run = DO_FLASH;
	} else {
		LOGV("Unknown parameter: %s", argv[1]);
		goto usage;
	}
uid:
	LOGV("------------");

	uid = getuid();
	LOGV("Current uid: %d", uid);

	if (uid == 0)
		goto root;

	memset(&capheader, 0, sizeof(capheader));
	memset(&capdata, 0, sizeof(capdata));
	capheader.version = _LINUX_CAPABILITY_VERSION_3;
	capdata[CAP_TO_INDEX(CAP_SETUID)].effective |= CAP_TO_MASK(CAP_SETUID);
	capdata[CAP_TO_INDEX(CAP_SETGID)].effective |= CAP_TO_MASK(CAP_SETGID);
	capdata[CAP_TO_INDEX(CAP_SETUID)].permitted |= CAP_TO_MASK(CAP_SETUID);
	capdata[CAP_TO_INDEX(CAP_SETGID)].permitted |= CAP_TO_MASK(CAP_SETGID);

	LOGV("Setting capabilities");
	if (capset(&capheader, &capdata[0]) < 0) {
		LOGE("Could not set capabilities: %s", strerror(errno));
	}

	LOGV("Attempting to escalate to root");
	if (setresgid(0, 0, 0) || setresuid(0, 0, 0)) {
		LOGE("setresgid/setresuid failed");
	}

	uid = getuid();
	LOGV("Current uid: %d", uid);

	if (uid) {
		LOGE("Failed to gain root access... :(");
		return 1;
	}
root:
	LOGV("We have root access!");

	if (run == DO_EXEC)
		goto exec;

	if (run == DO_SU)
		goto su;

	if (run == DO_FLASH)
		goto flash;

	return 0;
exec:
	LOGV("------------");

	argc_exec = argc - 2; // drop name and -exec
	argv_exec = malloc((argc_exec + 1) * sizeof(void*)); // add 1 for NULL
	argv_exec[argc_exec] = 0;

	// place arguments after exec into argv_exec
	for (i = 2; i < argc; i++)
		argv_exec[i - 2] = argv[i];

	LOGV("Executing: '%s' with %d arguments\n",
		argv_exec[0], argc_exec - 1);
	execvp(argv_exec[0], argv_exec);

	// if we get this far, then execvp failed!
	LOGV("Failed to execute '%s'!", argv_exec[0]);

	free(argv_exec);
	return 1;
su:
	LOGV("------------");

	argv_exec = malloc(2 * sizeof(void*)); // add 1 for NULL
	argv_exec[0] = "-sh";
	argv_exec[1] = 0;

	LOGV("Starting root shell");
	execve("/system/bin/sh", argv_exec, 0);

	// if we get this far, then execve failed!
	LOGV("Failed to start root shell!");
	return 1;
flash:
	ret = flash_permissive_boot();
	if (ret)
		goto oops;

	return 0;
usage:
	LOGE("Usage for %s (%s):", argv[0], APP_NAME);
	LOGE("  Execute a command as root:");
	LOGE("    %s exec command [args...]", argv[0]);
	LOGE("  Start a root shell:");
	LOGE("    %s su", argv[0]);
	LOGE("  Rebuild boot partition in permissive mode:");
	LOGE("    %s flash", argv[0]);
	return EINVAL;
oops:
	LOGE("Failed! Exiting...");
	return ret;
}
