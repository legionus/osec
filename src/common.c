/* common.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2010  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "osec.h"

extern char *progname;

int
__attribute__ ((format (printf, 1, 2)))
osec_error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	return 0;
}

void
__attribute__ ((noreturn))
__attribute__ ((format (printf, 3, 4)))
osec_fatal(const int exitnum, const int errnum, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (errnum > 0)
		fprintf(stderr, ": %s\n", strerror(errnum));
	exit(exitnum);
}
