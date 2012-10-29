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

char *progname;

void  *read_buf;
size_t read_bufsize;

// FIXME: use config file for this variables.
char def_db_path[] = "/tmp/osec";
char *db_path = NULL;

static void __attribute__ ((noreturn))
print_help(int ret)  {
	printf("Usage: osec-migrade-db [-h | -D <dbpath>] <DBFILE>\n");
	exit(ret);
}

static char *
decode_dirname(char *dir) {
	char *ndir = NULL;
	size_t len = strlen(dir);
	unsigned int i, j = 0;
	int found = 0, ret;

	ndir = (char *) xmalloc(sizeof(char) * len);

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
		}
		else {
			if (found)
				ndir[j++] = dir[i];
		}
	}

	if (!found) {
		xfree(ndir);
		return NULL;
	}

	ndir[j++] = '\0';
	ndir = (char *) xrealloc(ndir,(sizeof(char) * j));

	return ndir;
}

static void
osec_empty_digest(struct record *rec) {
	char fdigest[digest_len];
	bzero(&fdigest, (size_t) digest_len);
	append_value(OVALUE_CSUM, &fdigest, (size_t) digest_len, rec);
}

static void
osec_empty_symlink(struct record *rec) {
	char t = '\0';
	append_value(OVALUE_LINK, &t, (size_t) 1, rec);
}

static void
gen_db_name(char *dirname, char **dbname) {
	int i = 0;
	size_t j = strlen(db_path) + 10;
	size_t len = j + strlen(dirname);

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
	size_t klen, len = 0;
	char *dbfile, *dbnewfile, *dbtemp, *dirname = NULL;
	char *key;
	unsigned cpos;
	struct cdb cdbm;
	struct cdb_make cdbn;

	struct record rec;

	progname = basename(argv[0]);

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

	// Allocate buffer for reading files.
	read_bufsize = (size_t) (sysconf(_SC_PAGE_SIZE) - 1);
	read_buf = xmalloc(read_bufsize);

	/*
	 * Set default data buffer. This value will increase in the process of
	 * creating a database.
	 */
	rec.len  = 1024;
	rec.data = xmalloc(rec.len);

	cdb_seqinit(&cpos, &cdbm);
	while(cdb_seqnext(&cpos, &cdbm) > 0) {
		char *type;

		klen = cdb_keylen(&cdbm);
		key = (char *) xmalloc((size_t) (klen + 1));

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
			osec_state(&rec, &st);

			if (cdb_make_add(&cdbn, key, (unsigned) klen+1, rec.data, (unsigned) rec.offset) != 0)
				osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", key);
		}

		xfree(key);
	}

	write_db_version(&cdbn);

	xfree(rec.data);

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

	xfree(dbtemp);
	xfree(dirname);
	xfree(dbnewfile);

	return EXIT_SUCCESS;
}
