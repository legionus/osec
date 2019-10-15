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

void
exclude_match_append(char *pattern)
{
	size_t len = strlen(pattern);

	if (!len)
		return;
	len++;

	exclude_matches = (char *) xrealloc(exclude_matches,
	                                    (sizeof(char) * (exclude_matches_len + sizeof(size_t) + len)));

	memcpy((exclude_matches + exclude_matches_len), &len, sizeof(size_t));
	exclude_matches_len += sizeof(size_t);

	memcpy((exclude_matches + exclude_matches_len), pattern, len);
	exclude_matches_len += len;
}

void
exclude_matches_file(char *file)
{
	FILE *fd;
	char *line = NULL;
	ssize_t len;
	size_t bufsiz = 0;

	if ((fd = fopen(file, "r")) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "%s: fopen", file);

	while ((len = getline(&line, &bufsiz, fd)) != -1) {
		unsigned int i = 0;

		while (isspace(line[i]))
			i++;

		if (strlen((line + i)) == 0 || line[i] == '#')
			continue;

		if (line[len - 1] == '\n')
			line[len - 1] = '\0';

		exclude_match_append(line + i);
	}
	xfree(line);

	if (fclose(fd) != 0)
		osec_fatal(EXIT_FAILURE, errno, "%s: fclose", file);
}

int
is_exclude(char *str)
{
	size_t siz, len = 0;

	if (!exclude_matches_len)
		return 0;

	while (len < exclude_matches_len) {
		memcpy(&siz, (exclude_matches + len), sizeof(size_t));
		len += sizeof(size_t);

		if (fnmatch((exclude_matches + len), str, FNM_NOESCAPE) == 0)
			return 1;
		len += siz;
	}
	return 0;
}
