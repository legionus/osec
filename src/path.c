/* path.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2009  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "osec.h"

extern char *db_path;

static int
remove_recursive(char *fname) {
	DIR *d;
	struct dirent *dir;
	struct stat st;
	int retval = 1;

	if (lstat(fname, &st) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: lstat", fname);

	if (!S_ISDIR(st.st_mode)) {
		remove(fname);
		return retval;
	}

	if ((d = opendir(fname)) == NULL) {
		if (errno == EACCES) {
			osec_error("%s: opendir: %s\n", fname, strerror(errno));
			return 0;
		}
		else
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

	if (retval)
		remove(fname);

	return retval;
}

void
recreate_tempdir(void) {
	struct stat st;
	char *tempdir = NULL;

	/* tempdir = db_path/temp */
	size_t len = strlen(db_path) + 6;

	tempdir = (char *) xmalloc(sizeof(char) * len);
	sprintf(tempdir, "%s/temp", db_path);

	if (lstat(tempdir, &st) == -1) {
		if (errno != ENOENT)
			osec_fatal(EXIT_FAILURE, errno, "%s: lstat", tempdir);
	}
	else if(remove_recursive(tempdir) == 0)
		osec_fatal(EXIT_FAILURE, 0, "%s: remove_recursive: Unable to remove tempdir\n", tempdir);

	if (mkdir(tempdir, 0700) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkdir", tempdir);

	free(tempdir);
}

char *
validate_path(const char *path) {
	unsigned int i, j = 0;
	char *buf = NULL;
	size_t len;

	len = strlen(path);

	if (path[0] != '/' ||
	    strstr(path, "/../") != NULL ||
	    strstr(path, "/./" ) != NULL) {
		osec_error("Canonical path required\n");
		return buf;
	}

	buf = (char *) xmalloc(sizeof(char) * (len+1));
	buf[j++] = '/';

	for(i = 1; i < len; i++) {
		if (path[i-1] == '/' && path[i] == '/')
			continue;
		buf[j++] = path[i];
	}
	buf[j] = '\0';

	if (buf[j-1] == '/')
		buf[j-1] = '\0';

	if (j < len)
		buf = xrealloc(buf, sizeof(char) * j);

	return buf;
}
