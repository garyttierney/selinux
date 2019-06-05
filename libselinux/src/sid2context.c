#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include "selinux_internal.h"
#include "policy.h"

int security_sid_to_context_raw(const char *sid, char **con)
{
	char path[PATH_MAX];
	char *buf = NULL;
	int size, bufsz;
	int fd, ret = -1;
	errno = ENOENT;

	if (!selinux_mnt) {
		return -1;
	}

	snprintf(path, sizeof path, "%s/sid2context", selinux_mnt);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}

	errno = EINVAL;
	size = selinux_page_size;
	buf = malloc(size);
	if (!buf) {
		goto out;
	}

	bufsz = snprintf(buf, size, "%s", sid);
	if (bufsz >= size || bufsz < 0) {
		goto out;
	}

	// clear errno for write()
	errno = 0;
	ret = write(fd, buf, strlen(buf));
	if (ret < 0) {
		goto out;
	}

	memset(buf, 0, size);
	ret = read(fd, buf, size - 1);
	if (ret < 0) {
		goto out;
	}

	*con = strdup(buf);
	if (!*sid) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(buf);
	close(fd);
	return ret;
}

hidden_def(security_sid_to_context_raw)

int security_sid_to_context(const char *sid, char **con)
{
	char *rcon = NULL;
	int ret;

	if (security_sid_to_context_raw(sid, &rcon)) {
		return -EINVAL;
	}

	ret = selinux_raw_to_trans_context(rcon, con);
	freecon(rcon);
	return ret;
}

hidden_def(security_sid_to_context)
