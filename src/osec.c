/* osec.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 * Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fts.h>

#include <gcrypt.h>

#include "osec.h"

// FIXME: use config file for this variables.
char def_db_path[] = "/tmp/osec";
char def_user[] = "osec";
char def_group[] = "osec";

char *exclude_matches = NULL;
size_t exclude_matches_len = 0;

char *db_path = NULL;
int read_only = 0;
int numeric_user_group = 0;
unsigned ignore = 0;
const hash_type_data_t *hash_type = NULL;

static void print_help(int ret)
{
	printf("Usage: %1$s [OPTIONS] [DIRECTORY...]\n"
	       "   or: %1$s [OPTIONS] --file=FILE [DIRECTORY...]\n"
	       "\n"
	       "This utility help you to see difference between\n"
	       "two states of your system.\n"
	       "\n"
	       "Options:\n"
	       "  -r, --read-only           work in read-only mode;\n"
	       "  -R, --allow-root          allow run with root priveleges;\n"
	       "  -n, --numeric-ids         dont convert uid/gid into username;\n"
	       "  -u, --user=USER           non-privelege user account name;\n"
	       "  -g, --group=GROUP         non-privelege group account name;\n"
	       "  -D, --dbpath=PATH         path to the directory with databases;\n"
	       "  -f, --file=FILE           obtain directories from file FILE;\n"
	       "  -x, --exclude=PATTERN     exclude files matching PATTERN;\n"
	       "  -X, --exclude-from=FILE   read exclude patterns from FILE;\n"
	       "  -i, --ignore=LIST         dont show changes: checksum, symlink,\n"
	       "                            user, group, mode, mtime or inode;\n"
	       "  -t, --hash-type=NAME      use specified hash type,\n"
	       "                            currently supported hash types:\n"
	       "                            sha1, sha256, sha512, stribog512,\n"
	       "                            default is sha1;\n"
	       "  -v, --version             print program version and exit;\n"
	       "  -h, --help                output a brief help message.\n"
	       "\n",
	       program_invocation_short_name);
	exit(ret);
}

static void print_version(void)
{
	printf("%s version " PACKAGE_VERSION "\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Modified by Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "\n"
	       "Copyright (C) 2008-2012  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	       program_invocation_short_name);
	exit(EXIT_SUCCESS);
}

static bool gen_db_name(char *dirname, char **dbname)
{
	int i = 0;
	size_t j = strlen(db_path) + 10;
	size_t len = j + strlen(dirname);

	*dbname = malloc(sizeof(char) * len);

	if (*dbname == NULL) {
		osec_error("malloc: %m");
		return false;
	}

	sprintf(*dbname, "%s/osec.cdb.", db_path);

	while (dirname[i] != '\0') {
		if ((j + 3) >= len) {
			len += 32;
			*dbname = realloc(*dbname, sizeof(char) * len);
			if (*dbname == NULL) {
				osec_error("realloc: %m");
				return false;
			}
		}

		if (!isprint(dirname[i]) || (dirname[i] == '/')) {
			sprintf(((*dbname) + j), "%%%02X", (unsigned char) dirname[i]);
			j += 3;
		} else if (dirname[i] == '%') {
			(*dbname)[j++] = '%';
			(*dbname)[j++] = '%';
		} else
			(*dbname)[j++] = dirname[i];
		i++;
	}
	(*dbname)[j++] = '\0';

	if (j < len) {
		*dbname = realloc(*dbname, sizeof(char) * j);
		if (*dbname == NULL) {
			osec_error("realloc: %m");
			return false;
		}
	}

	return true;
}

static int dsort(const FTSENT **a, const FTSENT **b)
{
	if (S_ISDIR((*a)->fts_statp->st_mode)) {
		if (!S_ISDIR((*b)->fts_statp->st_mode))
			return 1;
	} else if (S_ISDIR((*b)->fts_statp->st_mode))
		return -1;
	return (strcmp((*a)->fts_name, (*b)->fts_name));
}

static bool create_cdb(int fd, char *dir,
		const hash_type_data_t *primary_type_data,
		const hash_type_data_t *secondary_type_data)
{
	FTS *t;
	FTSENT *p;
	char *argv[2];

	struct stat st;
	struct cdb_make cdbm;
	bool retval = false;

	struct record rec = { 0 };

	if (cdb_make_start(&cdbm, fd) < 0) {
		osec_error("cdb_make_start: %m");
		goto end;
	}

	if (lstat(dir, &st) == -1 || !S_ISDIR(st.st_mode))
		goto skip;

	argv[0] = dir;
	argv[1] = NULL;

	if ((t = fts_open(argv, FTS_PHYSICAL, dsort)) == NULL) {
		osec_error("fts_open: %s: %m", dir);
		goto end;
	}

	/*
	 * Set default data buffer. This value will increase in the process of
	 * creating a database.
	 */
	rec.len = 1024;
	rec.data = malloc(rec.len);

	if (rec.data == NULL) {
		osec_error("malloc: %m");
		goto end;
	}

	while ((p = fts_read(t))) {
		rec.offset = 0;

		switch (p->fts_info) {
			case FTS_DNR:
			case FTS_ERR:
			case FTS_NS:
				osec_error("fts_read: %s: %m", p->fts_path);
				continue;
			case FTS_D:
			case FTS_DC:
			case FTS_F:
			case FTS_SL:
			case FTS_SLNONE:
				break;
			default:
				continue;
		}

		if (is_exclude(p->fts_path))
			continue;

		if (!osec_state(&rec, p->fts_statp) ||
		    !osec_xattr(&rec, p->fts_path))
			goto end;

		switch (p->fts_info) {
			case FTS_F:
				if (!osec_digest(&rec, p->fts_path, primary_type_data, secondary_type_data))
					goto end;
				break;
			case FTS_SL:
			case FTS_SLNONE:
				if (!osec_symlink(&rec, p->fts_path))
					goto end;
				break;
		}

		if (cdb_make_add(&cdbm, p->fts_path, (unsigned) p->fts_pathlen + 1,
		                 rec.data, (unsigned) rec.offset) != 0) {
			osec_error("cdb_make_add: %s: %m", p->fts_path);
			goto end;
		}
	}

	if (fts_close(t) == -1) {
		osec_error("fts_close: %s: %m", dir);
		goto end;
	}

skip:
	if (!write_db_version(&cdbm, primary_type_data, secondary_type_data))
		goto end;

	if (cdb_make_finish(&cdbm) < 0) {
		osec_error("cdb_make_finish: %m");
		goto end;
	}

	retval = true;
end:
	free(rec.data);
	return retval;
}

static bool show_changes(struct cdb *new_cdb, struct cdb *old_cdb,
		const hash_type_data_t *hashtype_data)
{
	int rc;
	bool retval = false;
	char *key = NULL;
	void *old_data = NULL, *new_data = NULL;
	unsigned cpos;
	size_t klen, old_dlen, new_dlen;

	size_t key_len = 0;
	size_t old_data_len = 0;
	size_t new_data_len = 0;

	cdb_seqinit(&cpos, new_cdb);

	while ((rc = cdb_seqnext(&cpos, new_cdb)) > 0) {
		char *p;

		klen = cdb_keylen(new_cdb);

		if (klen > key_len) {
			key_len += klen - key_len;
			p = realloc(key, key_len + 1);
			if (p == NULL) {
				osec_error("realloc: %m");
				goto end;
			}
			key = p;
		}

		if (cdb_read(new_cdb, key, (unsigned) klen, cdb_keypos(new_cdb)) < 0) {
			osec_error("cdb_read: %m");
			goto end;
		}

		if (key[0] != '/')
			continue;

		key[klen] = '\0';

		new_dlen = cdb_datalen(new_cdb);

		if (new_dlen > new_data_len) {
			new_data_len += new_dlen - new_data_len;
			p = realloc(new_data, new_data_len);

			if (p == NULL) {
				osec_error("realloc: %m");
				goto end;
			}
			new_data = p;
		}

		if (cdb_read(new_cdb, new_data, (unsigned) new_dlen, cdb_datapos(new_cdb)) < 0) {
			osec_error("cdb_read: %m");
			goto end;
		}

		// Search
		if (old_cdb != NULL && cdb_find(old_cdb, key, (unsigned) klen) > 0) {
			old_dlen = (size_t) cdb_datalen(old_cdb);

			if (old_dlen > old_data_len) {
				old_data_len += old_dlen - old_data_len;
				p = realloc(old_data, old_data_len);

				if (p == NULL) {
					osec_error("realloc: %m");
					goto end;
				}
				old_data = p;
			}

			if (cdb_read(old_cdb, old_data, (unsigned) old_dlen, cdb_datapos(old_cdb)) < 0) {
				osec_error("cdb_read: %m");
				goto end;
			}

			rc = check_difference(key, new_data, new_dlen,
					old_data, old_dlen, hashtype_data);
			if (rc < 0)
				goto end;
			if (!rc && !check_bad_files(key, new_data, new_dlen))
				goto end;
		} else {
			if (!check_new(key, new_data, new_dlen, hashtype_data))
				goto end;
		}
	}

	if (rc < 0) {
		osec_error("cdb_seqnext(new_cdb): %m");
		goto end;
	}

	retval = true;
end:
	free(new_data);
	free(old_data);
	free(key);

	return retval;
}

static bool show_oldfiles(struct cdb *new_cdb, struct cdb *old_cdb,
		const hash_type_data_t *hashtype_data)
{
	int rc;
	bool retval = false;
	char *key = NULL;
	void *data = NULL;
	unsigned cpos, klen;

	size_t key_len = 0;
	size_t data_len = 0;

	cdb_seqinit(&cpos, old_cdb);

	while ((rc = cdb_seqnext(&cpos, old_cdb)) > 0) {
		char *p;

		klen = cdb_keylen(old_cdb);

		if (klen > key_len) {
			key_len += klen - key_len;
			p = realloc(key, key_len + 1);

			if (p == NULL) {
				osec_error("realloc: %m");
				goto end;
			}
			key = p;
		}

		if (cdb_read(old_cdb, key, klen, cdb_keypos(old_cdb)) < 0) {
			osec_error("cdb_read: %m");
			goto end;
		}

		if (key[0] != '/')
			continue;

		key[klen] = '\0';

		if (cdb_find(new_cdb, key, klen) == 0) {
			unsigned dlen = cdb_datalen(old_cdb);

			if (dlen > data_len) {
				data_len += dlen - data_len;
				p = realloc(data, data_len);

				if (p == NULL) {
					osec_error("realloc: %m");
					goto end;
				}
				data = p;
			}

			if (cdb_read(old_cdb, data, dlen, cdb_datapos(old_cdb)) < 0) {
				osec_error("cdb_read: %m");
				goto end;
			}

			if (!check_removed(key, data, (size_t) dlen, hashtype_data))
				goto end;
		}
	}

	if (rc < 0) {
		osec_error("cdb_seqnext(old_cdb): %m");
		goto end;
	}

	retval = true;
end:
	free(key);
	free(data);

	return retval;
}

static bool database_get_hashes(struct cdb *cdbm,
		const hash_type_data_t **new_hash,
		const hash_type_data_t **old_hash)
{
	size_t buffersize = 0;
	char *buffer = NULL;

	if (cdb_find(cdbm, "hashnames", strlen("hashnames")) == 0) {
		osec_error("cdb_read(hashnames): %m");
		return false;
	}

	buffersize = cdb_datalen(cdbm);
	buffer = malloc(buffersize);

	if (buffer == NULL) {
		osec_error("malloc: %m");
		return false;
	}

	if (cdb_read(cdbm, buffer, (unsigned) buffersize, cdb_datapos(cdbm)) < 0) {
		osec_error("cdb_read(hashnames): %m");
		free(buffer);
		return false;
	}

	if (!get_hashes_from_string(buffer, buffersize, new_hash, old_hash)) {
		free(buffer);
		return false;
	}

	free(buffer);
	return true;
}

static bool process(char *dirname)
{
	size_t len;
	bool retval = false;
	int new_fd, old_fd;
	char *new_dbname, *old_dbname;
	struct cdb old_cdb, new_cdb;

	const hash_type_data_t *primary_type_data = NULL;
	const hash_type_data_t *secondary_type_data = NULL;

	if (is_exclude(dirname))
		return true;

	// Generate priv state database name
	if (!gen_db_name(dirname, &old_dbname))
		return false;

	new_fd = old_fd = -1;
	new_dbname = NULL;

	// Open old database
	errno = 0;
	if ((old_fd = open(old_dbname, OSEC_O_FLAGS)) != -1) {
		if (!compat_db_version(old_fd)) {
			osec_error("file not look like osec database: %s", old_dbname);
			goto end;
		}

		printf("Processing %s ...\n", dirname);
	} else if (errno == ENOENT) {
		dbversion = 0;
		printf("Init database for %s ...\n", dirname);
	} else {
		osec_error("open: %s: %m", old_dbname);
		goto end;
	}

	// Generate new state database
	len = strlen(db_path) + 21;
	new_dbname = malloc(sizeof(char) * len);

	if (new_dbname == NULL) {
		osec_error("malloc: %m");
		goto end;
	}

	sprintf(new_dbname, "%s/temp/osec.XXXXXXXXX", db_path);

	// Open new database
	if ((new_fd = mkstemp(new_dbname)) == -1) {
		osec_error("mkstemp: %s: %m", new_dbname);
		goto end;
	}

	// Unlink termporary file
	if (read_only) {
		if (remove(new_dbname) == -1)
			osec_error("remove: %s: %m", new_dbname);
	}

	primary_type_data = hash_type;
	secondary_type_data = hash_type;

	if (old_fd != -1) {
		const hash_type_data_t *old_hash = NULL;
		const hash_type_data_t *new_hash = NULL;

		if (cdb_init(&old_cdb, old_fd) < 0) {
			osec_error("cdb_init(old_cdb): %m");
			goto end;
		}

		if (dbversion >= 4) {
			if (!database_get_hashes(&old_cdb, &new_hash, &old_hash))
				goto end;
		} else {
			old_hash = new_hash = get_hash_type_data_by_name("sha1", strlen("sha1"));
			if (new_hash == NULL) {
				osec_error("failed to find hash type 'sha1'");
				goto end;
			}
		}

		/*
		 * if old hash and new hash from database doesn't match with requested type, use last requested hash type
		 */
		if (((old_hash == NULL) || (strcmp(old_hash->hashname, hash_type->hashname) != 0)) &&
		    (strcmp(new_hash->hashname, hash_type->hashname) != 0)) {
			secondary_type_data = new_hash;
		}
	}

	// Create new state
	if (!create_cdb(new_fd, dirname, primary_type_data, secondary_type_data))
		goto end;

	if (cdb_init(&new_cdb, new_fd) < 0) {
		osec_error("cdb_init(new_cdb): %m");
		goto end;
	}

	if (old_fd != -1) {
		if (!show_changes(&new_cdb, &old_cdb, secondary_type_data) ||
		    !show_oldfiles(&new_cdb, &old_cdb, secondary_type_data))
			goto end;
	} else {
		if (!show_changes(&new_cdb, NULL, primary_type_data))
			goto end;
	}

	retval = true;
end:
	if (old_fd != -1 && close(old_fd) == -1) {
		osec_error("close: %s :%m", old_dbname);
		goto end;
	}

	if (close(new_fd) == -1) {
		osec_error("close: %s: %m", new_dbname);
		goto end;
	}

	//replace database with new
	if (retval && !read_only && rename(new_dbname, old_dbname) == -1) {
		osec_error("remove: %s -> %s: %m", old_dbname, new_dbname);
		retval = false;
	}

	free(old_dbname);
	free(new_dbname);

	return retval;
}

int main(int argc, char **argv)
{
	int c;
	int retval = EXIT_SUCCESS;
	int allow_root = 0;
	char *dirslist_file = NULL;
	char *user = NULL, *group = NULL;

	gcry_error_t gcrypt_error;

	struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ "read-only", no_argument, 0, 'r' },
		{ "allow-root", no_argument, 0, 'R' },
		{ "numeric-ids", no_argument, 0, 'n' },
		{ "ignore", required_argument, 0, 'i' },
		{ "dbpath", required_argument, 0, 'D' },
		{ "file", required_argument, 0, 'f' },
		{ "user", required_argument, 0, 'u' },
		{ "group", required_argument, 0, 'g' },
		{ "exclude", required_argument, 0, 'x' },
		{ "exclude-from", required_argument, 0, 'X' },
		{ "hash-type", required_argument, 0, 't' },
		{ 0, 0, 0, 0 }
	};

	hash_type = get_hash_type_data_by_name("sha1", strlen("sha1"));

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long(argc, argv, "hvnrRi:u:g:D:f:x:X:t:", long_options, NULL)) != -1) {
		switch (c) {
			case 'v':
				print_version();
				break;
			case 'n':
				numeric_user_group = 1;
				break;
			case 'r':
				read_only = 1;
				break;
			case 'R':
				allow_root = 1;
				break;
			case 'u':
				user = optarg;
				break;
			case 'g':
				group = optarg;
				break;
			case 'i':
				process_ignore(optarg);
				break;
			case 'D':
				db_path = optarg;
				break;
			case 'f':
				dirslist_file = optarg;
				break;
			case 'x':
				if (!exclude_match_append(optarg))
					exit(EXIT_FAILURE);
				break;
			case 'X':
				if (!exclude_matches_file(optarg))
					exit(EXIT_FAILURE);
				break;
			case 't':
				hash_type = get_hash_type_data_by_name(optarg, strlen(optarg));
				if (hash_type == NULL)
					osec_fatal(EXIT_FAILURE, 0, "unknown hash type: %s", optarg);
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if (db_path == NULL)
		db_path = def_db_path;

	//drop program privileges if we are root
	if (!allow_root && !geteuid()) {
		drop_privs((user != NULL ? user : def_user),
		           (group != NULL ? group : def_group));

		if (!geteuid())
			osec_fatal(EXIT_FAILURE, 0, "cannot run from under privilege user");
	}

	// initialize libgcrypt
	if (!gcry_check_version(GCRYPT_VERSION)) {
		osec_fatal(EXIT_FAILURE, 0, "libgcrypt version mismatch");
	}

	gcrypt_error = gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
	if (gcry_err_code(gcrypt_error) != GPG_ERR_NO_ERROR) {
		errno = gcry_err_code_to_errno(gcry_err_code(gcrypt_error));

		osec_fatal(EXIT_FAILURE, 0, "gcry_control error: %s, source: %s: %m",
				gcry_strerror(gcrypt_error),
				gcry_strsource(gcrypt_error));
	}

	gcrypt_error = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (gcry_err_code(gcrypt_error) != GPG_ERR_NO_ERROR) {
		errno = gcry_err_code_to_errno(gcry_err_code(gcrypt_error));

		osec_fatal(EXIT_FAILURE, 0, "gcry_control error: %s, source: %s: %m",
				gcry_strerror(gcrypt_error),
				gcry_strsource(gcrypt_error));
	}

	recreate_tempdir();

	char path[MAXPATHLEN];

	if (dirslist_file != NULL) {
		FILE *fd;
		char *line = NULL;
		size_t len = 0;
		ssize_t n;

		if ((fd = fopen(dirslist_file, "r")) == NULL)
			osec_fatal(EXIT_FAILURE, errno, "%s: fopen", dirslist_file);

		while ((n = getline(&line, &len, fd)) != -1) {
			int i = 0;

			while (isspace(line[i]))
				i++;

			if (strlen((line + i)) == 0 || line[i] == '#')
				continue;

			if (line[n - 1] == '\n')
				line[n - 1] = '\0';

			if (!validate_path(line + i, path))
				continue;

			if (!process(path))
				retval = EXIT_FAILURE;
		}

		free(line);

		if (fclose(fd) != 0)
			osec_fatal(EXIT_FAILURE, errno, "%s: fclose", dirslist_file);
	}

	while (optind < argc) {
		if (!validate_path(argv[optind++], path))
			continue;

		if (!process(path))
			retval = EXIT_FAILURE;
	}

	free(exclude_matches);

	return retval;
}
