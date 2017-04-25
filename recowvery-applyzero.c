#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>


#define APP_NAME  "recowvery"
#define HOST_NAME "applyzero(enter to recovery)"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO,  APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { __android_log_print(ANDROID_LOG_ERROR, APP_NAME, __VA_ARGS__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#endif

#define SEP LOGV("------------")

#include "bootimg.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* msm8996 */
#define FILE_SIZE 41943040
#define BLOCK_RECOVERY "/dev/block/bootdevice/by-name/recovery"
#define BLOCK_ZERO "/dev/zero"


#define NEW_FILE_PERMISSIONS (S_IRUSR | S_IWUSR | S_IRGRP)

static int flash_zero_boot(const int to_boot)
{
	int size, fd_scr, fd_dst,ret, ret2;
	char *buf;

	fd_scr = open(BLOCK_ZERO, O_RDONLY |  O_BINARY);
	if (fd_scr < 0) {
		LOGV("open %s failed\n", FILE_BOOT);
		return 1;
		}
	fd_dst = open(BLOCK_RECOVERY, O_CREAT | O_RDWR | O_BINARY, NEW_FILE_PERMISSIONS);
	if (fd_dst < 0) {
		LOGV("open %s failed\n", BLOCK_RECOVERY);
		return 1;
	}
	buf = malloc(FILE_SIZE);

	ret2 = read(fd_scr,buf, FILE_SIZE);
	LOGV("read conut %d\n", ret2);
	ret = write(fd_dst,buf,FILE_SIZE);

	LOGV("write conut %d\n", ret);
	LOGV("Use reboot recovery to enter to fastboot mode");
	close(fd_scr);
	close(fd_dst);

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	LOGV("Welcome to %s! (%s)", APP_NAME, HOST_NAME);

	if (argc > 1 && !strcmp(argv[1], "boot"))
		ret = flash_zero_boot(1);
	else
		ret = flash_zero_boot(0);
	if (ret)
		goto oops;

	return 0;
oops:
	LOGE("Error %d: %s", ret, strerror(ret));
	LOGE("Exiting...");
	return ret;
}
