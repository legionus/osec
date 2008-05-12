#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "osec.h"

int
osec_error(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", PACKAGE_NAME);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	return 0;
}

void __attribute__ ((noreturn))
osec_fatal(const int exitnum, const int errnum, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", PACKAGE_NAME);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (errnum > 0)
		fprintf(stderr, ": %s\n", strerror(errnum));
	exit(exitnum);
}
