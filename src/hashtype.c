// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: hashtype.c
 *
 * Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 */

#include "osec.h"

#include <gcrypt.h>

static hash_type_data_t data[] = {
	{ GCRY_MD_SHA1, "sha1" },
	{ GCRY_MD_SHA256, "sha256" },
	{ GCRY_MD_SHA512, "sha512" },
	{ GCRY_MD_STRIBOG512, "stribog512" },
};

const hash_type_data_t *get_hash_type_data_by_name(const char *hashname,
		const size_t hashname_len)
{
	size_t i = 0;

	for (i = 0; i < sizeof(data) / sizeof(data[0]); ++i) {
		if (hashname_len == strlen(data[i].hashname) &&
		    !memcmp(data[i].hashname, hashname, hashname_len)) {
			return &data[i];
		}
	}

	return NULL;
}
