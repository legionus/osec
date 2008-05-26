/* digest.c
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
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

void
digest(const char *fname, char *out) {
	int fd;
	ssize_t num;
	SHA_CTX ctx;

	void *buf;
	size_t size = sysconf(_SC_PAGE_SIZE) - 1;

	if ((fd = open(fname, O_RDONLY)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", fname);

	SHA1_Init(&ctx);

	buf = xmalloc(size);
	while ((num = read(fd, buf, size)) > 0)
		SHA1_Update(&ctx, buf, (int) num);
	xfree(buf);

	if (num == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: read", fname);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", fname);

	SHA1_Final((unsigned char *) out, &ctx);
	return;
}
