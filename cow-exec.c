#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/capability.h>

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, "cow-setprop", __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); fflush(stdout); }
#endif

int main(int argc, char **argv)
{
	struct __user_cap_header_struct capheader;
	struct __user_cap_data_struct capdata[2];
	bool do_exec = false;
	int uid, i, argc_exec;
	char** argv_exec;

	if (argc < 2)
		goto uid;

	if (strcmp(argv[1], "-exec") == 0) {
		if (argc == 2) {
			LOGV("Not enough parameters for exec!");
			goto usage;
		}
		do_exec = true;
	} else {
		LOGV("Unknown parameter: %s", argv[1]);
		goto usage;
	}
uid:
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
		LOGV("Could not set capabilities: %s", strerror(errno));
	}

	LOGV("Attempting to escalate to root");
	if (setresgid(0, 0, 0) || setresuid(0, 0, 0)) {
		LOGV("setresgid/setresuid failed");
	}

	uid = getuid();
	LOGV("Current uid: %d", uid);

	if (uid != 0) {
		LOGV("Failed to gain root access... :(");
		return 1;
	}
root:
	if (!do_exec) // not doing exec? we're done
		return 0;

	argc_exec = argc - 2; // drop (cow-exec/run-as) and -exec
	argv_exec = malloc((argc_exec + 1) * sizeof(void*)); // add 1 for NULL
	argv_exec[argc_exec] = NULL;

	// place arguments after exec into argv_exec
	for (i = 2; i < argc; i++)
		argv_exec[i - 2] = argv[i];

	LOGV("Executing: '%s' with %d arguments\n",
		argv_exec[0], argc_exec - 1);
	execvp(argv_exec[0], argv_exec);

	// if we get this far, then execvp failed!
	LOGV("Failed to execute '%s'!", argv_exec[0]);

	return 1;
usage:
	LOGV("Usage: %s -exec command [args...]", argv[0]);
	return EINVAL;
}
