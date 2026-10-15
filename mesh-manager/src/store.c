// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef STATE_DIR
#define STATE_DIR "/etc/mesh-manager"
#endif
#define LIMIT (1024 * 1024)
#define EXPECTED_LIMIT (256 * 1024)
#define RETRIES 8

static const char *filename(int argc, char **argv, int *cas, ssize_t *expected_size)
{
	static const char *allowed[] = {
		"state.json", "identity.json", "cluster.json", "backhaul.json", "jobs.json",
		"device.key", "device.crt", "network-ca.key", "network-ca.crt", "join-ca.crt"
	};
	if (argc == 1)
		return allowed[0];
	const char *name = NULL;
	if (argc == 2)
		name = argv[1];
	else if (argc == 4 && (!strcmp(argv[1], "--cas") || !strcmp(argv[1], "--remove-cas"))) {
		*cas = !strcmp(argv[1], "--remove-cas") ? 2 : 1;
		name = argv[2];
		if (*cas == 2 && strcmp(name, "network-ca.key")) return NULL;
		if (!strcmp(argv[3], "-1"))
			*expected_size = -1;
		else {
			const char *p = argv[3];
			size_t size = 0;
			if (*p < '1' || *p > '9') return NULL;
			for (; *p; p++) {
				if (*p < '0' || *p > '9' || size > EXPECTED_LIMIT / 10) return NULL;
				size = size * 10 + (size_t)(*p - '0');
				if (size > EXPECTED_LIMIT) return NULL;
			}
			*expected_size = (ssize_t)size;
		}
	}
	if (!name)
		return NULL;
	for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
		if (!strcmp(name, allowed[i]))
			return allowed[i];
	return NULL;
}

static int private_file(const struct stat *s)
{
	return S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
		(s->st_mode & 07777) == 0600 && s->st_nlink == 1;
}

static int same_file(const struct stat *a, const struct stat *b)
{
	return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
		a->st_size == b->st_size && a->st_mode == b->st_mode &&
		a->st_uid == b->st_uid && a->st_nlink == b->st_nlink &&
		a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
		a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int same_directory(int dir)
{
	struct stat actual, path;
	return !fstat(dir, &actual) && !lstat(STATE_DIR, &path) &&
		S_ISDIR(path.st_mode) && path.st_uid == geteuid() && !(path.st_mode & 0077) &&
		actual.st_dev == path.st_dev && actual.st_ino == path.st_ino;
}

/* Return2 only for an observed compare conflict. Unsafe/uncertain I/O is1,
 * never an absent sentinel. The fd/path/stat checks reject inode ABA even if
 * the displayed JSON and secret redaction would look unchanged. */
static int compare(int dir, const char *target, const char *expected, ssize_t size,
	const struct stat *original, struct stat *captured)
{
	struct stat before, after, path;
	int fd = -1, result = 1;
	char buffer[4096], extra;
	if (size < 0) {
		if (!fstatat(dir, target, &path, AT_SYMLINK_NOFOLLOW)) return 2;
		return errno == ENOENT ? 0 : 1;
	}
	fd = openat(dir, target, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) return errno == ENOENT ? 2 : 1;
	if (fstat(fd, &before) || !private_file(&before) || before.st_size < 1 || before.st_size > EXPECTED_LIMIT) goto done;
	if (before.st_size != size || (original && !same_file(original, &before))) { result = 2; goto done; }
	for (size_t offset = 0; offset < (size_t)size;) {
		ssize_t n = read(fd, buffer, (size_t)size - offset < sizeof(buffer) ? (size_t)size - offset : sizeof(buffer));
		if (n <= 0) goto done;
		if (memcmp(buffer, expected + offset, (size_t)n)) { result = 2; goto done; }
		offset += (size_t)n;
	}
	if (read(fd, &extra, 1) != 0 || fstat(fd, &after) || !private_file(&after) ||
		fstatat(dir, target, &path, AT_SYMLINK_NOFOLLOW)) goto done;
	if (!same_file(&before, &after) || !same_file(&after, &path)) { result = 2; goto done; }
	if (captured) *captured = after;
	result = 0;
done:
	if (close(fd)) result = 1;
	return result;
}

int main(int argc, char **argv)
{
	char tmp[64], buffer[4096];
	int cas = 0;
	ssize_t expected_size = 0;
	const char *target = filename(argc, argv, &cas, &expected_size);
	struct stat st, original, staging, stage_final, written;
	char *expected = NULL;
	size_t total = 0;
	ssize_t n;
	int dir = -1, fd = -1, rc = 1, created = 0, staged = 0;
	if (!target)
		goto fail;

	if (!mkdir(STATE_DIR, 0700))
		created = 1;
	else if (errno != EEXIST)
		goto fail;
	dir = open(STATE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dir < 0 || fstat(dir, &st) || st.st_uid != geteuid() || (st.st_mode & 0077))
		goto fail;
	if (flock(dir, LOCK_EX))
		goto fail;
	if (created) {
		char parent[sizeof(STATE_DIR)];
		char *slash;
		int parent_fd, flushed;

		memcpy(parent, STATE_DIR, sizeof(parent));
		slash = strrchr(parent, '/');
		if (!slash)
			goto fail;
		if (slash == parent)
			parent[1] = '\0';
		else
			*slash = '\0';
		parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (parent_fd < 0)
			goto fail;
		flushed = fsync(parent_fd);
		close(parent_fd);
		if (flushed)
			goto fail;
	}
	if (!same_directory(dir)) goto fail;
	if (cas) {
		if (cas == 2 && expected_size < 1) goto fail;
		if (expected_size > 0) {
			expected = malloc((size_t)expected_size);
			if (!expected) goto fail;
			for (size_t used = 0, retries = 0; used < (size_t)expected_size;) {
				n = read(STDIN_FILENO, expected + used, (size_t)expected_size - used);
				if (n < 0 && errno == EINTR && retries++ < RETRIES) continue;
				if (n <= 0) goto fail;
				used += (size_t)n;
			}
		}
		rc = compare(dir, target, expected, expected_size, NULL, &original);
		if (rc) goto fail;
		rc = 1;
	}
	if (cas == 2) {
		/* Retire only the transferred signing key, with the directory writer
		 * lock, original inode/bytes and durable directory deletion checked. */
		if (read(STDIN_FILENO, buffer, 1) != 0 || !same_directory(dir)) goto fail;
		rc = compare(dir, target, expected, expected_size, &original, NULL);
		if (rc) goto fail;
		rc = 1;
		if (unlinkat(dir, target, 0) || fsync(dir)) goto fail;
		rc = 0; goto fail;
	}
	if (!fstatat(dir, target, &st, AT_SYMLINK_NOFOLLOW) && !S_ISREG(st.st_mode))
		goto fail;
	/* A killed writer leaves at most one private staging file per allowed target. */
	snprintf(tmp, sizeof(tmp), ".%s.tmp", target);
	if (!fstatat(dir, tmp, &st, AT_SYMLINK_NOFOLLOW)) {
		if (!S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
		    (st.st_mode & 07777) != 0600 || st.st_nlink != 1 ||
		    st.st_size > LIMIT || unlinkat(dir, tmp, 0))
			goto fail;
	} else if (errno != ENOENT)
		goto fail;
	fd = openat(dir, tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0 || fchmod(fd, 0600) || fstat(fd, &staging))
		goto fail;
	staged = 1;
	written = staging;
	while ((n = read(STDIN_FILENO, buffer, sizeof(buffer))) != 0) {
		if (n < 0) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		total += (size_t)n;
		if (total > LIMIT - (cas && expected_size > 0 ? (size_t)expected_size : 0))
			goto fail;
		for (ssize_t offset = 0; offset < n;) {
			ssize_t wrote = write(fd, buffer + offset, (size_t)(n - offset));
			if (wrote < 0 && errno == EINTR)
				continue;
			if (wrote <= 0)
				goto fail;
			offset += wrote;
		}
		if (fstat(fd, &written)) goto fail;
	}
	/* Make contents durable before rename, then persist the directory entry. */
	if (!total || fsync(fd) || fstat(fd, &st) || !private_file(&st) ||
		st.st_dev != staging.st_dev || st.st_ino != staging.st_ino || st.st_size != (off_t)total || !same_file(&st, &written) ||
		fstatat(dir, tmp, &stage_final, AT_SYMLINK_NOFOLLOW) || !same_file(&st, &stage_final) || !same_directory(dir))
		goto fail;
	if (close(fd)) { fd = -1; goto fail; }
	fd = -1;
	if (cas) {
		rc = compare(dir, target, expected, expected_size, expected_size < 0 ? NULL : &original, NULL);
		if (rc) goto fail;
		rc = 1;
	}
	/* Kernel NOREPLACE makes the absent case conditional even if another
 * process creates the target between the final read and installation. */
	if (cas && expected_size < 0) {
#ifdef SYS_renameat2
		if (syscall(SYS_renameat2, dir, tmp, dir, target, 1U)) {
			if (errno == EEXIST) rc = 2;
			goto fail;
		}
#else
		goto fail;
#endif
	} else if (renameat(dir, tmp, dir, target)) goto fail;
	staged = 0;
	if (fsync(dir)) goto fail;
	rc = 0;
fail:
	if (rc)
		fputs(rc == 2 ? "mesh-manager: durable state compare conflict\n" : "mesh-manager: durable state write failed\n", stderr);
	if (fd >= 0) {
		close(fd);
	}
	if (rc && staged && dir >= 0 && !fstatat(dir, tmp, &st, AT_SYMLINK_NOFOLLOW) &&
		private_file(&st) && st.st_dev == staging.st_dev && st.st_ino == staging.st_ino && same_file(&st, &written))
		unlinkat(dir, tmp, 0);
	if (dir >= 0)
		close(dir);
	if (expected) { memset(expected, 0, (size_t)expected_size); free(expected); }
	return rc;
}
