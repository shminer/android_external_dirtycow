#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <cutils/properties.h>
#include <selinux/selinux.h>

#define APP_NAME "recowvery-app_process64"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#endif

const char* CONTEXT_SYS = "u:r:system_server:s0";
const char* PROP_KEY = "ctl.start";
const char* PROP_VAL = "flash_recovery";

int main(void)
{
	int ret = 1;
	char* conn = NULL;

	LOGV("Welcome to %s!", APP_NAME);
	LOGV("------------");

	ret = getcon(&conn);
	if (ret) {
		LOGV("Could not get current security context (ret = %d)!", ret);
		goto nope;
	}

	LOGV("Current selinux context: %s", conn);

	ret = setcon(CONTEXT_SYS);
	if (ret) {
		LOGV("Unable to set security context to '%s' (ret = %d)!",
			CONTEXT_SYS, ret);
		goto nope;
	}
	LOGV("Set context to '%s'!", CONTEXT_SYS);

	ret = getcon(&conn);
	if (ret) {
		LOGV("Could not get current security context (ret = %d)!", ret);
		goto nope;
	}

	if (strcmp(conn, CONTEXT_SYS) != 0) {
		LOGV("Current security context '%s' does not match '%s'!",
			conn, CONTEXT_SYS);
		ret = EINVAL;
		goto nope;
	}

	LOGV("Current security context: %s", conn);

	LOGV("Setting property '%s' to '%s'", PROP_KEY, PROP_VAL);

	ret = property_set(PROP_KEY, PROP_VAL);
	if (ret) {
		LOGV("Failed to set property '%s' (ret = %d)!", PROP_KEY, ret);
		goto nope;
	}

	LOGV("------------");
	LOGV("Recovery flash script should have started!");
	LOGV("Run on your PC to see progress: adb logcat -s recowvery-applypatch");
	/*
	 * we should wait 2 minutes to allow the flash to complete
	 */
	LOGV("Waiting 120 seconds...");
	sleep(120);
	return 0;
nope:
	/*
	 * we should wait 20 seconds just so Zygote isn't
	 * being constantly restarted
	 */
	LOGV("Waiting 20 seconds for next try...");
	sleep(20);
	return ret;
}
