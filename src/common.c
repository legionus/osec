// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: common.c
 *
 * Copyright (C) 2008-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
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
