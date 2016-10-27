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

const char* IMG_SRC = "/data/media/0/recovery.img";
const char* IMG_DEST = "/cache/recovery.img";

int copyfile(const char* src_file, const char* dest_file)
{
	char buf[16384];
	size_t f_sz = 0, bytes = 0, written = 0;
	FILE *f_in = NULL, *f_out = NULL;

	LOGV("Copying '%s' to '%s'", src_file, dest_file);

	f_in = fopen(src_file, "rb");
	if (f_in == NULL) {
		LOGV("Could not open '%s' in read mode!", src_file);
		return ENOENT;
	}

	f_out = fopen(dest_file, "wb");
	if (f_out == NULL) {
		LOGV("Could not open '%s' in write mode!", dest_file);
		fclose(f_in);
		return EACCES;
	}

	fseek(f_in, 0, SEEK_END);
	f_sz = ftell(f_in);
	fseek(f_in, 0, SEEK_SET);
	LOGV("Source file size: %zu bytes", f_sz);

	while ((bytes = fread(buf, 1, sizeof(buf), f_in)) > 0) {
		if (fwrite(buf, 1, bytes, f_out) != bytes) {
			LOGV("Write fail: %s", strerror(errno));
			fclose(f_out);
			fclose(f_in);
			return EIO;
		}
		written += bytes;
	}
	LOGV("Write complete, wrote %zu bytes", written);

	if (written != f_sz) {
		LOGV("Source size (%zu) does not match bytes written (%zu)!",
			f_sz, written);
		return 1;
	}

	return 0;
}

int main(void)
{
	int ret = 1;
	char* conn = NULL;

	LOGV("***********************************************");
	LOGV("*   wotzit doing this ain't no app_process64  *");
	LOGV("***********************************************");

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

	LOGV("***********************************************");
	LOGV("* the cache called, it wants its recovery.img *");
	LOGV("***********************************************");
	ret = copyfile(IMG_SRC, IMG_DEST);
	if (ret) {
		LOGV("Failed to copy!");
		goto nope;
	}

	LOGV("Setting property '%s' to '%s'", PROP_KEY, PROP_VAL);

	ret = property_set(PROP_KEY, PROP_VAL);
	if (ret) {
		LOGV("Failed to set property '%s' (ret = %d)!", PROP_KEY, ret);
		goto nope;
	}

	LOGV("Recovery flash script should have started!");
	LOGV("Run on your PC to see progress: adb logcat | grep cow");
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
