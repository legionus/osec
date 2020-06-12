/* dbversion.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2009  Alexey Gladkov <gladkov.alexey@gmail.com>
 * Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "osec.h"

int
compat_db_version(int fd)
{
	struct cdb cdbm;
	char key[] = "version";
	size_t klen = 7;

	if (cdb_init(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(db)");

	if (cdb_find(&cdbm, key, (unsigned) klen) == 0)
		return 0;

	if (cdb_read(&cdbm, &dbversion, sizeof(dbversion), cdb_datapos(&cdbm)) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_read(dbversion)");

	return 1;
}

void
write_db_version(struct cdb_make *cdbm, const hash_type_data_t *primary_type_data, const hash_type_data_t *secondary_type_data)
{
	int ver = OSEC_DB_VERSION;
	char *buffer;

	if (cdb_make_add(cdbm, "version", (unsigned) 7, &ver, (unsigned) sizeof(ver)) != 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_add");

	size_t hashes_len = strlen(primary_type_data->hashname);
	int use_secondary = 0;

	if (secondary_type_data && (strcmp(primary_type_data->hashname, secondary_type_data->hashname) != 0)) {
		hashes_len += strlen(secondary_type_data->hashname) + strlen(":");
		use_secondary = 1;
	}

	buffer = xmalloc(hashes_len + 1);
	strcpy(buffer, primary_type_data->hashname);

	if (use_secondary) {
		strcat(buffer, ":");
		strcat(buffer, secondary_type_data->hashname);
	}

	if (cdb_make_add(cdbm, "hashnames", strlen("hashnames"), buffer, (unsigned) hashes_len) != 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_add");

	xfree(buffer);
}

void
get_hashes_from_string(const char *buffer, const size_t buffer_len, const hash_type_data_t **new_hash, const hash_type_data_t **old_hash)
{
	const char *delim;
	const hash_type_data_t *tmp_ptr;

	delim = memchr(buffer, ':', buffer_len);
	if (delim == NULL) {
		if (old_hash)
			*old_hash = NULL;

		tmp_ptr = get_hash_type_data_by_name(buffer, buffer_len);
		if (!tmp_ptr)
			osec_fatal(EXIT_FAILURE, 0, "get_hashes_from_string: unknown hash type '%.*s'", (int) buffer_len, buffer);

		if (new_hash)
			*new_hash = tmp_ptr;
	} else {
		const char *new_delim;
		size_t first_len = (size_t)(delim - buffer);
		size_t second_len = buffer_len - first_len - 1;

		new_delim = memchr(delim + 1, ':', second_len);
		if (new_delim != NULL)
			osec_fatal(EXIT_FAILURE, 0, "cdb_read(hashnames): invalid hashnames value '%.*s'", (int) buffer_len, buffer);

		tmp_ptr = get_hash_type_data_by_name(delim + 1, second_len);
		if (!tmp_ptr)
			osec_fatal(EXIT_FAILURE, 0, "cdb_read(hashnames): unknown hash type '%.*s'", (int) second_len, delim + 1);

		if (old_hash)
			*old_hash = tmp_ptr;

		tmp_ptr = get_hash_type_data_by_name(buffer, first_len);
		if (!tmp_ptr)
			osec_fatal(EXIT_FAILURE, 0, "cdb_read(hashnames): unknown hash type '%.*s'", (int) first_len, buffer);

		if (new_hash)
			*new_hash = tmp_ptr;
	}
}
