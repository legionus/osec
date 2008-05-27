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

	if (cdb_find(&cdbm, key, klen) == 0)
		return 0;

	return 1;
}

void
write_db_version(struct cdb_make *cdbm) {
	int ver = OSEC_DB_VERSION;
	if (cdb_make_add(cdbm, "version", 7, &ver, sizeof(ver)) != 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_add");
}
