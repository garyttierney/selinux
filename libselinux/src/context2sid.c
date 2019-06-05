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

int security_context_to_sid_raw(const char *con, char **sid)
{
	char path[PATH_MAX];
	char *buf = NULL;
	int size, bufsz;
	int fd, ret = -1;
	errno = ENOENT;

	if (!selinux_mnt) {
		return -1;
	}

	snprintf(path, sizeof path, "%s/context2sid", selinux_mnt);
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

	bufsz = snprintf(buf, size, "%s", con);
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

	*sid = strdup(buf);
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

hidden_def(security_context_to_sid_raw)

int security_context_to_sid(const char *con, char **sid)
{
	char *rcon = NULL;
	int ret;

	if (selinux_trans_to_raw_context(con, &rcon)) {
		return -1;
	}

	ret = security_context_to_sid_raw(rcon, sid);
	freecon(rcon);
	return ret;
}

hidden_def(security_context_to_sid)
