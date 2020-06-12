/* exclude.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fnmatch.h>
#include "osec.h"

extern char *exclude_matches;
extern size_t exclude_matches_len;

bool exclude_match_append(char *pattern)
{
	char *ptr;
	size_t len = strlen(pattern);

	if (!len)
		return true;
	len++;

	ptr = realloc(exclude_matches,
			(sizeof(char) * (exclude_matches_len + sizeof(size_t) + len)));

	if (ptr == NULL) {
		osec_error("realloc: %m");
		return false;
	}
	exclude_matches = ptr;

	memcpy((exclude_matches + exclude_matches_len), &len, sizeof(size_t));
	exclude_matches_len += sizeof(size_t);

	memcpy((exclude_matches + exclude_matches_len), pattern, len);
	exclude_matches_len += len;

	return true;
}

bool exclude_matches_file(char *file)
{
	FILE *fd;
	char *line = NULL;
	ssize_t len;
	size_t bufsiz = 0;
	bool retval = false;

	if ((fd = fopen(file, "r")) == NULL) {
		osec_error("fopen: %s: %m", file);
		return false;
	}

	while ((len = getline(&line, &bufsiz, fd)) != -1) {
		unsigned int i = 0;

		while (isspace(line[i]))
			i++;

		if (strlen((line + i)) == 0 || line[i] == '#')
			continue;

		if (line[len - 1] == '\n')
			line[len - 1] = '\0';

		if (!exclude_match_append(line + i))
			goto end;
	}
	retval = true;
end:
	xfree(line);

	if (fclose(fd) != 0) {
		osec_error("fclose: %s: %m", file);
		retval = false;
	}

	return retval;
}

bool is_exclude(char *str)
{
	size_t siz, len = 0;

	if (!exclude_matches_len)
		return false;

	while (len < exclude_matches_len) {
		memcpy(&siz, (exclude_matches + len), sizeof(size_t));
		len += sizeof(size_t);

		if (fnmatch((exclude_matches + len), str, FNM_NOESCAPE) == 0)
			return true;
		len += siz;
	}

	return false;
}
