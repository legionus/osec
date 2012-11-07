/* digest.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"
#include "sha1.h"

void  *read_buf;
size_t read_bufsize;

void
digest_file(const char *fname, char *out) {
	int fd;
	long num;
	SHA_CTX ctx;

	if ((fd = open(fname, OSEC_O_FLAGS)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", fname);

	SHA1_Init(&ctx);

	/* Let the kernel know we are going to read everything in sequence. */
	(void) posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	while ((num = read(fd, read_buf, read_bufsize)) > 0)
		SHA1_Update(&ctx, read_buf, (unsigned long) num);

	if (num == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: read", fname);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", fname);

	SHA1_Final((unsigned char *) out, &ctx);
}

void
digest(const char *data, size_t len, char *out) {
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, len);
	SHA1_Final((unsigned char *) out, &ctx);
}
