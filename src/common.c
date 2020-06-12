/* common.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2010  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "osec.h"

int
osec_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", program_invocation_short_name);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	return 0;
}

void
osec_fatal(const int exitnum, const int errnum, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", program_invocation_short_name);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (errnum > 0)
		fprintf(stderr, ": %s", strerror(errnum));
	fprintf(stderr, "\n");
	exit(exitnum);
}
