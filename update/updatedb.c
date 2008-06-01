/* updatedb.c
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */

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

static void __attribute__ ((noreturn))
print_help(int ret)  {
	printf("Usage: osec-migrade-db [-h | -D <dbpath>] <DBFILE>\n");
	exit(ret);
}

static size_t
osec_empty_digest(void **val, size_t *vlen) {
	char fdigest[digest_len];
	bzero(&fdigest, digest_len);
	return append_value(OVALUE_CSUM, val, vlen, &fdigest, digest_len);
}

static size_t
osec_empty_symlink(void **val, size_t *vlen) {
	char t = '\0';
	return append_value(OVALUE_LINK, val, vlen, &t, 1);
}

static void
gen_db_name(char *dirname, char **dbname) {
	int i = 0;
	unsigned int j = strlen(db_path) + 10;
	unsigned int len = j + strlen(dirname);

	(*dbname) = (char *) xmalloc(sizeof(char) * len);
	sprintf((*dbname), "%s/osec.cdb.", db_path);

	while (dirname[i] != '\0') {
		if ((j+3) >= len) {
			len += 32;
			(*dbname) = (char *) xrealloc((*dbname), sizeof(char) * len);
		}

		if (!isprint(dirname[i]) || (dirname[i] == '/')) {
			sprintf(((*dbname) + j), "%%%02X", (unsigned char) dirname[i]);
			j += 3;
		}
		else if (dirname[i] == '%') {
			(*dbname)[j++] = '%';
			(*dbname)[j++] = '%';
		}
		else
			(*dbname)[j++] = dirname[i];
		i++;
	}
	(*dbname)[j++] = '\0';

	if (j < len)
		(*dbname) = (char *) xrealloc((*dbname), sizeof(char) * j);
}

int
main(int argc, char **argv) {
	int c, fd, fdtemp;
	size_t len = 0;
	char *dbfile, *dbnewfile, *dbtemp, *dirname = NULL;
	char *key;
	unsigned cpos, klen, dlen = 0;
	struct cdb cdbm;
	struct cdb_make cdbn;

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "dbpath",		required_argument,	0, 'D' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long (argc, argv, "hD:", long_options, NULL)) != -1) {
		switch (c) {
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
	dbtemp = (char *) xmalloc(sizeof(char) * len);
	sprintf(dbtemp, "%s.XXXXXXXXX", dbfile);

	// Open new database
	if ((fdtemp = mkstemp(dbtemp)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkstemp", dbtemp);

	if (cdb_make_start(&cdbn, fdtemp) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	cdb_seqinit(&cpos, &cdbm);
	while(cdb_seqnext(&cpos, &cdbm) > 0) {
		char *type;

		klen = cdb_keylen(&cdbm);
		key = (char *) xmalloc(klen + 1);

		if (cdb_read(&cdbm, key, klen, cdb_keypos(&cdbm)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		key[klen] = '\0';

		if ((type = strchr(key, '\0')) == (key + klen))
			osec_fatal(EXIT_FAILURE, errno, "strchr: Cant find type\n");

		klen = strlen(key);

		type += 1;
		if (strcmp(type, "stat") == 0) {
			void *val = NULL;
			size_t vlen = 0;
			struct stat st;

			if (cdb_read(&cdbm, &st, sizeof(st), cdb_datapos(&cdbm)) < 0)
				osec_fatal(EXIT_FAILURE, errno, "cdb_read");

			osec_empty_digest(&val, &vlen);
			osec_empty_symlink(&val, &vlen);
			osec_state(&val, &vlen, &st);

			if (cdb_make_add(&cdbn, key, klen+1, val, vlen) != 0)
				osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", key);

			xfree(val);
		}

		if (dirname != NULL) {
			if (dlen > klen) {
				xfree(dirname);
				dirname = strdup(key);
				dlen = klen;
			}
		}
		else {
			dirname = strdup(key);
			dlen = klen;
		}

		xfree(key);
	}

	write_db_version(&cdbn);

	if (cdb_make_finish(&cdbn) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	if (close(fdtemp) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbtemp);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbfile);

	remove(dbfile);

	gen_db_name(dirname, &dbnewfile);
	chmod(dbtemp, S_IRUSR|S_IWUSR|S_IRGRP);
	rename(dbtemp, dbnewfile);

	xfree(dbtemp);
	xfree(dirname);
	xfree(dbnewfile);

	return EXIT_SUCCESS;
}
