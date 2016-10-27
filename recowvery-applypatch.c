#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define APP_NAME "recowvery-applypatch"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#endif

const char* IMG_SRC = "/cache/recovery.img";
const char* IMG_DEST = "/dev/block/bootdevice/by-name/recovery"; // msm8996
//const char* IMG_DEST = "/dev/block/platform/155a0000.ufs/by-name/RECOVERY";

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
	int ret;

	LOGV("Flashing recovery image...");

	ret = copyfile(IMG_SRC, IMG_DEST);
	if (ret) {
		LOGV("Unable to flash recovery image!");
		LOGV(" :( ");
		goto exit;
	}

	LOGV("Recovery has been flashed successfully!")
	LOGV("You may use 'reboot recovery' now to enter recovery.");
	LOGV("***********************************************");
	LOGV("*       give jcadduono a hug, will ya?        *");
	LOGV("***********************************************");

exit:
	return ret;
}
