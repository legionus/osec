/* memory.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdlib.h>
#include <errno.h>
#include "osec.h"

void *
xmalloc(size_t size) {
	void *ptr;
	if ((ptr = malloc(size)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "malloc");
	return ptr;
}

void *
xrealloc(void *ptr, size_t size) {
	if ((ptr = realloc(ptr, size)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "realloc");
	return ptr;
}

void
xfree(void *ptr) {
	if (ptr != NULL)
		free(ptr);
}
