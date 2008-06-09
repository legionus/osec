/* dbversion.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "osec.h"

int
compat_db_version(int fd) {
	struct cdb cdbm;
	char   key[] = "version";
	size_t klen = 7;

	if (cdb_init(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(db)");

	if (cdb_find(&cdbm, key, (unsigned) klen) == 0)
		return 0;

	return 1;
}

void
write_db_version(struct cdb_make *cdbm) {
	int ver = OSEC_DB_VERSION;
	if (cdb_make_add(cdbm, "version", (unsigned) 7, &ver, (unsigned) sizeof(ver)) != 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_add");
}
