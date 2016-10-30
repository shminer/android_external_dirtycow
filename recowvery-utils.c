#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { __android_log_print(ANDROID_LOG_ERROR, APP_NAME, __VA_ARGS__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#endif

#include "bootimg.h"

#define MiB 1048576

static int write_binary_to_file(const char* file, const byte* binary, uint32_t size)
{
	int fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, 0666);

	if (fd < 0)
		goto oops;

	LOGV("Writing to file '%s'...", file);

	if (size > 0 && write(fd, binary, size) != size)
		goto oops;

	LOGV("Wrote OK: %lu bytes", (unsigned long)size);

	close(fd);
	return 0;
oops:
	LOGE("Could not write file '%s'", file);
	return EACCES;
}

static byte *cpio_file(const char *file, const byte *content, uint32_t content_len, uint32_t *cpio_len)
{
	struct stat st = {0};
	uint32_t sz = 0;
	uint32_t flen = strlen(file);
	byte *cpio, *c;

	st.st_mode |= S_IFREG; // is a file
	st.st_mode |= S_IRWXU | S_IRGRP | S_IXGRP; // permission mode 0750
	st.st_nlink = 1;
	st.st_mtime = time(0); // set modification to now
	st.st_size = content_len;

	// calculate length of the new cpio file
	*cpio_len = 110 + flen + 4 + content_len + 3;

	// allocate full memory needed to store cpio file
	c = cpio = malloc(*cpio_len);

	// write cpio header, content size, filename all in one go
	c += sprintf((char*)c,
		"070701"
		"%08X%08X%08X%08X%08X%08X"
		"%08X%08X%08X%08X%08X%08X"
		"00000000%s",
		(uint32_t)st.st_ino,
		(uint32_t)st.st_mode,
		(uint32_t)st.st_uid,
		(uint32_t)st.st_gid,
		(uint32_t)st.st_nlink,
		(uint32_t)st.st_mtime,
		(uint32_t)st.st_size,
		(uint32_t)major(st.st_dev),
		(uint32_t)minor(st.st_dev),
		(uint32_t)major(st.st_rdev),
		(uint32_t)minor(st.st_rdev),
		flen + 1, file);

	// add null padding
	memset(c, 0, 4);
	c += 4;

	// write content to cpio file
	memcpy(c, content, content_len);
	c += content_len;

	// add null padding
	memset(c, 0, 3);
	c += 3;

//	assert((c - cpio) != *cpio_len));

	return cpio;
}

static const byte cpio_trailer[124] = "07070100000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000B00000000TRAILER!!!\0\0\0\0";

static int cpio_append(const char *file, const byte *cpio, uint32_t cpio_len)
{
	int ret = 0;
	int fd, sz;
	const char trailer[10] = "TRAILER!!!";
	char tmp[sizeof(trailer)];

	fd = open(file, O_RDWR);
	if (fd < 0) {
		LOGE("Could not open cpio archive '%s' as r/w!", file);
		goto oops;
	}

	sz = lseek(fd, 0, SEEK_END);
	if (sz < 0)
		goto oops;

	LOGV("Opened cpio archive '%s' (%lu bytes)", file, (unsigned long)sz);

	// search for cpio trailer
	lseek(fd, -4 - sizeof(trailer), SEEK_CUR);
	read(fd, tmp, sizeof(trailer));
	if (memcmp(trailer, tmp, sizeof(tmp))) {
		lseek(fd, 0, SEEK_END);
		goto append; // no valid trailer, append to the end anyway
	}

	// seek to the start of trailer
	lseek(fd, -sizeof(cpio_trailer), SEEK_END);

append:
	if (write(fd, cpio, cpio_len) != cpio_len) {
		ret = EIO;
		goto trailer;
	}

	LOGV("Wrote new file (%lu bytes) to cpio archive,", (unsigned long)cpio_len);
trailer:
	if (write(fd, cpio_trailer, sizeof(cpio_trailer)) != sizeof(cpio_trailer)) {
		ret = EIO;
		goto oops;
	}

	sz = lseek(fd, 0, SEEK_END);
	LOGV("Final size: %lu bytes", (unsigned long)sz);
oops:
	if (fd >= 0)
		close(fd);

	return ret;
}

static int valid_filesize(const char *file, unsigned long size)
{
	int fd;
	unsigned long sz;

	LOGV("Checking '%s' for validity (size >= %lu bytes)", file, size);
	fd = open(file, O_RDONLY);
	if (fd < 0) {
		LOGE("Couldn't open file for reading!");
		return ENOENT;
	}
	sz = lseek(fd, 0, SEEK_END);
	LOGV("'%s': %lu bytes", file, sz);
	if (sz < size) {
		LOGE("File is not at least %lu bytes, must not be valid", size);
		close(fd);
		return EINVAL;
	}
	LOGV("File OK");
	close(fd);
	return 0;
}

static int decompress_ramdisk(const char *ramdisk, const char *cpio)
{
	int ret = 0;
	char cmd[100];

	LOGV("Decompressing ramdisk (gzip -d)");

	sprintf(cmd, "gzip -d < \"%s\" > \"%s\"", ramdisk, cpio);
	system(cmd);

	ret = valid_filesize(cpio, 4*MiB);
	if (ret)
		goto oops;

	LOGV("Decompression of ramdisk successful");

	LOGV("Deleting '%s' (no longer needed)", ramdisk);
	remove(ramdisk);

	return 0;
oops:
	LOGE("Ramdisk decompression failed!");
	return ret;
}

static int compress_ramdisk(const char *cpio, const char *ramdisk)
{
	int ret = 0;
	char cmd[100];

	LOGV("Compressing cpio to ramdisk (gzip -9 -c)");

	sprintf(cmd, "gzip -9 -c < \"%s\" > \"%s\"", cpio, ramdisk);
	system(cmd);

	ret = valid_filesize(ramdisk, 2*MiB);
	if (ret)
		goto oops;

	LOGV("Compression of ramdisk successful");

	LOGV("Deleting '%s' (no longer needed)", cpio);
	remove(cpio);

	return 0;
oops:
	LOGE("Ramdisk compression failed!");
	return ret;
}
