/* osec.h
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 * Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#ifndef OSEC_H
#define OSEC_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <cdb.h>

#define OSEC_O_FLAGS (O_RDONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW)

// OSEC_DB_VERSION 1 - start versioning
// OSEC_DB_VERSION 2 - mtime added
// OSEC_DB_VERSION 3 - xattr added
// OSEC_DB_VERSION 4 - csum now contains pairs of "hash name" and "hash value"
// OSEC_DB_VERSION 5 - mtime_nsec added
#define OSEC_DB_VERSION 5
int dbversion;

#define OSEC_CSM (1 << 1)
#define OSEC_LNK (1 << 2)
#define OSEC_MTS (1 << 3)
#define OSEC_UID (1 << 4)
#define OSEC_GID (1 << 5)
#define OSEC_MOD (1 << 6)
#define OSEC_INO (1 << 7)

#define OVALUE_XATTR 8
#define OVALUE_LINK 4
#define OVALUE_CSUM 2
#define OVALUE_STAT 1

typedef long long int osec_time_t;

typedef struct osec_stat {
	dev_t dev;         /* ID of device containing file */
	ino_t ino;         /* inode number */
	mode_t mode;       /* file's permission bits */
	uid_t uid;         /* user ID of owner */
	gid_t gid;         /* group ID of owner */
	osec_time_t mtime; /* time of last modification */
	osec_time_t mtime_nsec;
} osec_stat_t;

struct record {
	void *data;
	size_t len;
	size_t offset;
};

struct field {
	unsigned type;
	size_t len;
	void *data;
};

struct csum_field {
	size_t name_len;
	size_t data_len;
	const char *name;
	void *data;
};

typedef struct hash_type_data {
	int gcrypt_hashtype;
	const char *hashname;
} hash_type_data_t;

#define digest_len_sha1 20 /* SHA1 */

/* common.c */
void osec_fatal(const int exitnum, const int errnum, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)))
	__attribute__((noreturn));

int osec_error(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

/* memory.c */
void *xmempcpy(void *dest, const void *src, size_t n);
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void xfree(void *ptr);

/* privs.c */
void drop_privs(char *user, char *group)
	__attribute__((nonnull(1, 2)));

/* status.c */
void check_new(const char *fname, void *data, size_t len, const hash_type_data_t *hashtype_data)
	__attribute__((nonnull(1, 2, 4)));

/* Return 1 if check is true. Otherwise, 0 is returned. */
int check_insecure(osec_stat_t *st)
	__attribute__((nonnull(1)));

int check_difference(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen, const hash_type_data_t *hashtype_data)
	__attribute__((nonnull(1, 2, 4, 6)));

int check_bad_files(const char *fname, void *data, size_t len)
	__attribute__((nonnull(1, 2)));

int check_removed(const char *fname, void *data, size_t len, const hash_type_data_t *hashtype_data)
	__attribute__((nonnull(1, 2, 4)));

/* dbvalue.c */
void *osec_field(const unsigned type, const void *data, const size_t dlen, struct field *ret)
	__attribute__((nonnull(2)));

void append_value(const unsigned type, const void *src, const size_t slen, struct record *rec)
	__attribute__((nonnull(2, 4)));

void osec_state(struct record *rec, const struct stat *st)
	__attribute__((nonnull(1, 2)));

void osec_digest(struct record *rec, const char *fname, const hash_type_data_t *primary_type_data, const hash_type_data_t *secondary_type_data)
	__attribute__((nonnull(1, 2, 3, 4)));

void osec_symlink(struct record *rec, const char *fname)
	__attribute__((nonnull(1, 2)));

void osec_xattr(struct record *rec, const char *fname)
	__attribute__((nonnull(1, 2)));

void *osec_csum_field(const char *name, size_t namelen, const void *data, size_t dlen, struct csum_field *ret)
	__attribute__((nonnull(1, 3)));

void *osec_csum_field_next(const void *data, const size_t dlen, struct csum_field *ret, size_t *ret_len)
	__attribute__((nonnull(1)));

void osec_csum_append_value(const char *name, size_t namelen, const void *src, const size_t slen, struct record *rec)
	__attribute__((nonnull(1, 3, 5)));

/* dbvalue.c */
int compat_db_version(int fd);

void write_db_version(struct cdb_make *cdbm, const hash_type_data_t *primary_type_data, const hash_type_data_t *secondary_type_data)
	__attribute__((nonnull(1, 2)));

void get_hashes_from_string(const char *buffer, const size_t buffer_len, const hash_type_data_t **new_hash, const hash_type_data_t **old_hash)
	__attribute__((nonnull(1)));

/* exclude.c */
int is_exclude(char *file)
	__attribute__((nonnull(1)));

void exclude_match_append(char *pattern)
	__attribute__((nonnull(1)));

void exclude_matches_file(char *file)
	__attribute__((nonnull(1)));

/* ignore.c */
void process_ignore(const char *param)
	__attribute__((nonnull(1)));

/* path.c */
void recreate_tempdir(void);
bool validate_path(const char *path, char *ret)
	__attribute__((nonnull(1, 2)));

/* hashtype.c */
const hash_type_data_t *get_hash_type_data_by_name(const char *hashname, const size_t hashname_len)
	__attribute__((nonnull(1)));

#endif /* OSEC_H */
