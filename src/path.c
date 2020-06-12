/* path.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2009  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "osec.h"

extern char *db_path;

static int
remove_recursive(char *fname)
{
	DIR *d;
	struct dirent *dir;
	struct stat st;
	int retval = 1;

	if (lstat(fname, &st) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: lstat", fname);

	if (!S_ISDIR(st.st_mode)) {
		if (remove(fname) == -1)
			osec_error("remove: %s: %m", fname);
		return retval;
	}

	if ((d = opendir(fname)) == NULL) {
		if (errno == EACCES) {
			osec_error("opendir: %s: %m", fname);
			return 0;
		} else
			osec_fatal(EXIT_FAILURE, errno, "%s: opendir", fname);
	}

	if (chdir(fname) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: chdir", fname);

	while ((dir = readdir(d)) != NULL) {
		if ((!strncmp(dir->d_name, "..", (size_t) 2) || !strncmp(dir->d_name, ".", (size_t) 1)))
			continue;

		if ((retval = remove_recursive(dir->d_name)) == 0)
			break;
	}

	if (chdir("..") == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: chdir", fname);

	if (closedir(d) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: closedir", fname);

	if (retval && remove(fname) == -1)
		osec_error("remove: %s: %m", fname);

	return retval;
}

void
recreate_tempdir(void)
{
	struct stat st;
	static char tempdir[MAXPATHLEN];

	snprintf(tempdir, sizeof(tempdir), "%s/temp", db_path);

	errno = 0;
	if (lstat(tempdir, &st) == -1 && errno != ENOENT)
		osec_fatal(EXIT_FAILURE, errno, "%s: lstat", tempdir);

	if (errno == 0 && remove_recursive(tempdir) == 0)
		osec_fatal(EXIT_FAILURE, 0, "%s: remove_recursive: Unable to remove tempdir", tempdir);

	if (mkdir(tempdir, 0700) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkdir", tempdir);
}

bool
validate_path(const char *path, char *ret)
{
	if (path[0] != '/' ||
	    strstr(path, "/../") != NULL ||
	    strstr(path, "/./") != NULL) {
		osec_error("Canonical path required: %s", path);
		return false;
	}

	unsigned int j = 0;
	size_t len = strlen(path);

	ret[j++] = '/';

	for (unsigned int i = 1; i < len; i++) {
		if (path[i - 1] == '/' && path[i] == '/')
			continue;
		ret[j++] = path[i];
	}
	ret[j] = '\0';

	if (ret[j - 1] == '/')
		ret[j - 1] = '\0';

	return true;
}
