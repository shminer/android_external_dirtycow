#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/capability.h>

#define APP_NAME "recowvery"

#ifdef DEBUG
#include <android/log.h>
#define LOGV(...) { __android_log_print(ANDROID_LOG_INFO, APP_NAME, __VA_ARGS__); printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { __android_log_print(ANDROID_LOG_ERROR, APP_NAME, __VA_ARGS__); fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#else
#define LOGV(...) { printf(__VA_ARGS__); printf("\n"); }
#define LOGE(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }
#endif

enum {
	DO_NOTHING = 0,
	DO_EXEC,
	DO_SU
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
	} else {
		LOGV("Unknown parameter: %s", argv[1]);
		goto usage;
	}
uid:
	LOGV("------------");

	uid = getuid();
	LOGV("Current uid: %d", uid);

	if (!uid)
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

	if (!uid)
		goto oops;
root:
	LOGV("We have root access!");

	if (run == DO_EXEC)
		goto exec;

	if (run == DO_SU)
		goto su;

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
	free(argv_exec);
	ret = 1;
	goto oops;
su:
	LOGV("------------");

	argv_exec = malloc(2 * sizeof(void*)); // add 1 for NULL
	argv_exec[0] = "-sh";
	argv_exec[1] = 0;

	LOGV("Starting root shell");
	execve("/system/bin/sh", argv_exec, 0);

	// if we get this far, then execve failed!
	ret = 1;
	goto oops;
usage:
	LOGE("Usage for %s (%s):", argv[0], APP_NAME);
	LOGE("  Execute a command as root:");
	LOGE("    %s exec command [args...]", argv[0]);
	LOGE("  Start a root shell:");
	LOGE("    %s su", argv[0]);
	return EINVAL;
oops:
	LOGE("Failed! Exiting...");
	return ret;
}
