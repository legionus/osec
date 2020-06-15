// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: dbversion.c
 *
 * Copyright (C) 2008-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 * Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "osec.h"

bool compat_db_version(int fd)
{
	struct cdb cdbm;
	char key[] = "version";
	size_t klen = 7;
	int dbversion;

	if (cdb_init(&cdbm, fd) < 0) {
		osec_error("cdb_init(db): %m");
		return false;
	}

	if (cdb_find(&cdbm, key, (unsigned) klen) == 0)
		return false;

	if (cdb_read(&cdbm, &dbversion, sizeof(dbversion), cdb_datapos(&cdbm)) < 0) {
		osec_error("cdb_read(dbversion): %m");
		return false;
	}

	current_db.version = dbversion;

	return true;
}

bool write_db_metadata(struct cdb_make *cdbm)
{
	int ver = OSEC_DB_VERSION;
	size_t len = sizeof(ver);

	if (cdb_make_add(cdbm, "version", (unsigned) 7, &ver, (unsigned) len) != 0) {
		osec_error("cdb_make_add: %m");
		return false;
	}

	len = sizeof(char) * strlen(current_db.basepath);
	len += 1;

	if (cdb_make_add(cdbm, "basepath", (unsigned) 8, current_db.basepath, (unsigned) len) != 0) {
		osec_error("cdb_make_add: %m");
		return false;
	}

	len = strlen(current_db.primary_hashtype->hashname);
	int use_secondary = 0;

	if (current_db.secondary_hashtype &&
	    strcmp(current_db.primary_hashtype->hashname, current_db.secondary_hashtype->hashname) != 0) {
		len += strlen(current_db.secondary_hashtype->hashname) + strlen(":");
		use_secondary = 1;
	}

	char *buffer = malloc(len + 1);

	if (buffer == NULL) {
		osec_error("malloc: %m");
		return false;
	}

	strcpy(buffer, current_db.primary_hashtype->hashname);

	if (use_secondary) {
		strcat(buffer, ":");
		strcat(buffer, current_db.secondary_hashtype->hashname);
	}

	if (cdb_make_add(cdbm, "hashnames", strlen("hashnames"), buffer, (unsigned) len) != 0) {
		osec_error("cdb_make_add: %m");
		free(buffer);
		return false;
	}

	free(buffer);

	return true;
}

bool
get_hashes_from_string(const char *buffer, const size_t buffer_len, const hash_type_data_t **new_hash, const hash_type_data_t **old_hash)
{
	const char *delim;
	const hash_type_data_t *tmp_ptr;

	delim = memchr(buffer, ':', buffer_len);
	if (delim == NULL) {
		if (old_hash)
			*old_hash = NULL;

		tmp_ptr = get_hash_type_data_by_name(buffer, buffer_len);
		if (!tmp_ptr) {
			osec_error("get_hashes_from_string: unknown hash type '%.*s'", (int) buffer_len, buffer);
			return false;
		}

		if (new_hash)
			*new_hash = tmp_ptr;
	} else {
		const char *new_delim;
		size_t first_len = (size_t)(delim - buffer);
		size_t second_len = buffer_len - first_len - 1;

		new_delim = memchr(delim + 1, ':', second_len);
		if (new_delim != NULL) {
			osec_error("cdb_read(hashnames): invalid hashnames value '%.*s'", (int) buffer_len, buffer);
			return false;
		}

		tmp_ptr = get_hash_type_data_by_name(delim + 1, second_len);
		if (!tmp_ptr) {
			osec_error("cdb_read(hashnames): unknown hash type '%.*s'", (int) second_len, delim + 1);
			return false;
		}

		if (old_hash)
			*old_hash = tmp_ptr;

		tmp_ptr = get_hash_type_data_by_name(buffer, first_len);
		if (!tmp_ptr) {
			osec_error("cdb_read(hashnames): unknown hash type '%.*s'", (int) first_len, buffer);
			return false;
		}

		if (new_hash)
			*new_hash = tmp_ptr;
	}

	return true;
}
