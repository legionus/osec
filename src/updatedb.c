// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: updatedb.c
 *
 *  Copyright (C) 2008-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 *  Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"

// FIXME: use config file for this variables.
char def_db_path[] = "/tmp/osec";
char *db_path = NULL;

static void print_help(int ret)
{
	printf("Usage: %s [options] <DBFILE>\n"
	       "\n"
	       "Options:\n"
	       "  -D, --dbpath=PATH   path to the directory with databases;\n"
	       "  -V, --version       print program version and exit;\n"
	       "  -h, --help          output a brief help message.\n"
	       "\n",
	       program_invocation_short_name);
	exit(ret);
}

static void print_version(void)
{
	printf("%s version " PACKAGE_VERSION "\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2013-2020  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	       program_invocation_short_name);
	exit(EXIT_SUCCESS);
}

static char *decode_dirname(char *dir)
{
	char *ndir = NULL;
	size_t len = strlen(dir);
	unsigned int i, j = 0;
	int found = 0, ret;

	ndir = (char *) malloc(sizeof(char) * len);

	if (!ndir) {
		osec_error("malloc: %m");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < len; i++) {
		int c;
		if (dir[i] == '%') {
			found = 1;
			sscanf((dir + i), "%%%d%%", &c);
			if ((ret = snprintf(NULL, (size_t) 0, "%d", c)) == -1)
				osec_fatal(EXIT_FAILURE, 0,
				           "%s: snprintf: Unable to get length of char\n", dir);
			i += (unsigned int) (ret + 1);
			if (found)
				ndir[j++] = (char) c;
		} else {
			if (found)
				ndir[j++] = dir[i];
		}
	}

	if (!found) {
		free(ndir);
		return NULL;
	}

	ndir[j++] = '\0';
	ndir = realloc(ndir, (sizeof(char) * j));

	if (!ndir) {
		osec_error("realloc: %m");
		exit(EXIT_FAILURE);
	}

	return ndir;
}

static void osec_empty_digest(struct record *rec)
{
	struct record local_rec;

	char fdigest[digest_len_sha1];
	bzero(&fdigest, (size_t) digest_len_sha1);

	local_rec.data = NULL;
	local_rec.len = 0;
	local_rec.offset = 0;

	if (!osec_csum_append_value("sha1", sizeof("sha1") - 1, fdigest, digest_len_sha1, &local_rec))
		exit(EXIT_FAILURE);

	if (!append_value(OVALUE_CSUM, local_rec.data, local_rec.offset, rec))
		exit(EXIT_FAILURE);

	free(local_rec.data);
}

static void osec_empty_symlink(struct record *rec)
{
	char t = '\0';
	if (!append_value(OVALUE_LINK, &t, (size_t) 1, rec))
		exit(EXIT_FAILURE);
}

static void gen_db_name(char *dirname, char **dbname)
{
	int i = 0;
	size_t j = strlen(db_path) + 10;
	size_t len = j + strlen(dirname);

	*dbname = malloc(sizeof(char) * len);

	if (!(*dbname)) {
		osec_error("malloc: %m");
		exit(EXIT_FAILURE);
	}

	sprintf((*dbname), "%s/osec.cdb.", db_path);

	while (dirname[i] != '\0') {
		if ((j + 3) >= len) {
			len += 32;
			(*dbname) = realloc((*dbname), sizeof(char) * len);

			if (!(*dbname)) {
				osec_error("realloc: %m");
				exit(EXIT_FAILURE);
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
		(*dbname) = realloc((*dbname), sizeof(char) * j);

		if (!(*dbname)) {
			osec_error("realloc: %m");
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv)
{
	int c, fd, fdtemp;
	size_t klen, len = 0;
	char *dbfile, *dbnewfile, *dbtemp, *dirname = NULL;
	char *key;
	unsigned cpos;
	struct cdb cdbm;
	struct cdb_make cdbn;

	struct record rec;

	const hash_type_data_t *tmp_ptr;

	struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ "dbpath", required_argument, 0, 'D' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long(argc, argv, "hvD:", long_options, NULL)) != -1) {
		switch (c) {
			case 'v':
				print_version();
				break;
			case 'D':
				db_path = optarg;
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if (db_path == NULL)
		db_path = def_db_path;

	if (optind == argc)
		print_help(EXIT_FAILURE);

	dbfile = argv[optind];

	// Open old database
	if ((fd = open(dbfile, O_RDONLY | O_NOFOLLOW | O_NOCTTY)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", dbfile);

	if (compat_db_version(fd)) {
		printf("%s: Database already in new format\n", dbfile);
		return EXIT_SUCCESS;
	}

	if (cdb_init(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(cdbm)");

	// Generate new state database
	len = strlen(dbfile) + 11;
	dbtemp = malloc(sizeof(char) * len);

	if (!dbtemp) {
		osec_error("malloc: %m");
		exit(EXIT_FAILURE);
	}

	sprintf(dbtemp, "%s.XXXXXXXXX", dbfile);

	// Open new database
	if ((fdtemp = mkstemp(dbtemp)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkstemp", dbtemp);

	if (cdb_make_start(&cdbn, fdtemp) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	/*
	 * Set default data buffer. This value will increase in the process of
	 * creating a database.
	 */
	rec.len = 1024;
	rec.data = malloc(rec.len);

	if (!rec.data) {
		osec_error("malloc: %m");
		exit(EXIT_FAILURE);
	}

	cdb_seqinit(&cpos, &cdbm);
	while (cdb_seqnext(&cpos, &cdbm) > 0) {
		char *type;

		klen = cdb_keylen(&cdbm);
		key = malloc((size_t)(klen + 1));

		if (!key) {
			osec_error("malloc: %m");
			exit(EXIT_FAILURE);
		}

		if (cdb_read(&cdbm, key, (unsigned) klen, cdb_keypos(&cdbm)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		key[klen] = '\0';

		if ((type = strchr(key, '\0')) == (key + klen))
			osec_fatal(EXIT_FAILURE, errno, "strchr: Cant find type\n");

		klen = strlen(key);

		type += 1;
		if (strcmp(type, "stat") == 0) {
			struct stat st;

			rec.offset = 0;

			if (cdb_read(&cdbm, &st, (unsigned) sizeof(st), cdb_datapos(&cdbm)) < 0)
				osec_fatal(EXIT_FAILURE, errno, "cdb_read");

			osec_empty_digest(&rec);
			osec_empty_symlink(&rec);

			if (!osec_state(&rec, &st))
				exit(EXIT_FAILURE);

			if (cdb_make_add(&cdbn, key, (unsigned) klen + 1, rec.data, (unsigned) rec.offset) != 0)
				osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", key);
		}

		free(key);
	}

	tmp_ptr = get_hash_type_data_by_name("sha1", strlen("sha1"));
	if (tmp_ptr == NULL)
		osec_fatal(EXIT_FAILURE, 0, "failed to find hash type 'sha1'\n");

	if (!write_db_version(&cdbn, tmp_ptr, NULL))
		exit(EXIT_FAILURE);

	free(rec.data);

	if (cdb_make_finish(&cdbn) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	if (close(fdtemp) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbtemp);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbfile);

	dirname = decode_dirname(dbfile);
	gen_db_name(dirname, &dbnewfile);

	rename(dbtemp, dbnewfile);
	remove(dbfile);

	free(dbtemp);
	free(dirname);
	free(dbnewfile);

	return EXIT_SUCCESS;
}
