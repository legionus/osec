// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: osec2txt.c
 *
 *  Copyright (C) 2009-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 *  Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 */
#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"

struct database_metadata current_db = { 0 };

static void print_help(int ret)
{
	printf("Usage: %s [options] <DBFILE> <OUTFILE>\n"
	       "\n"
	       "Options:\n"
	       "  -V, --version   print program version and exit;\n"
	       "  -h, --help      output a brief help message.\n"
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
	       "Copyright (C) 2009-2020  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	       program_invocation_short_name);
	exit(EXIT_SUCCESS);
}

static void show_digest(int fd, const char *dst, size_t len)
{
	size_t i = 0;
	while (i < len)
		dprintf(fd, "%02x", (unsigned char) dst[i++]);
}

static void dump_record(int fd, char *key, void *rec, size_t rlen)
{
	osec_stat_t *st;
	int i;
	char *field;
	struct field field_data;

	if ((st = osec_field(OVALUE_STAT, rec, rlen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'stat' from dbvalue", key);

	i = 0;
	dprintf(fd, "file=\"");
	while (key[i]) {
		if (key[i] == '"' || key[i] == '\\')
			dprintf(fd, "\\");
		dprintf(fd, "%c", key[i]);
		i++;
	}
	dprintf(fd, "\" \\\n");

	if (current_db.version > 2) {
		if ((field = (char *) osec_field(OVALUE_XATTR, rec, rlen, &field_data)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'xattr' from dbvalue", key);

		dprintf(fd, "\txattr=\"");
		show_digest(fd, field, field_data.len);
		dprintf(fd, "\" \\\n");
	}

	if (S_ISREG(st->mode)) {
		if ((field = (char *) osec_field(OVALUE_CSUM, rec, rlen, &field_data)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'checksum' from dbvalue", key);

		if (current_db.version >= 4) {
			struct csum_field csum_field_data;

			while (field_data.len > 0) {
				field = osec_csum_field_next(field, field_data.len, &csum_field_data, &(field_data.len));
				if (field == NULL)
					osec_fatal(EXIT_FAILURE, 0,
					           "%s: osec_field: too short",
					           key);

				dprintf(fd, "\tchecksum=\"%.*s:", (int) csum_field_data.name_len, csum_field_data.name);
				show_digest(fd, csum_field_data.data, csum_field_data.data_len);
				dprintf(fd, "\" \\\n");
			}
		} else {
			dprintf(fd, "\tchecksum=\"sha1:");
			show_digest(fd, field, digest_len_sha1);
			dprintf(fd, "\" \\\n");
		}
	}

	if (S_ISLNK(st->mode)) {
		if ((field = (char *) osec_field(OVALUE_LINK, rec, rlen, NULL)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'symlink' from database value", key);

		if (field) {
			i = 0;
			dprintf(fd, "\tsymlink=\"");
			while (field[i]) {
				if (field[i] == '"' || field[i] == '\\')
					dprintf(fd, "\\");
				dprintf(fd, "%c", field[i]);
				i++;
			}
			dprintf(fd, "\" \\\n");
		}
	}

	dprintf(fd, "\tino=%ld \\\n", st->ino);
	dprintf(fd, "\tdev=%lld \\\n", (long long) st->dev);
	dprintf(fd, "\tmode=\\%06lo \\\n", (unsigned long) st->mode);
	dprintf(fd, "\tuid=%ld \\\n", (long) st->uid);
	dprintf(fd, "\tgid=%ld \\\n", (long) st->gid);
	if (current_db.version > 1) {
		dprintf(fd, "\tmtime=%lld", st->mtime);
		dprintf(fd, ".%09lld0", (current_db.version > 4) ? st->mtime_nsec : 0);
		dprintf(fd, "\n");
	} else {
		dprintf(fd, "\tmtime=0.0\n");
	}
}

static void print_meta(struct cdb *cdbm, const char *name, int outfd)
{
	if (cdb_find(cdbm, name, (unsigned) strlen(name)) <= 0)
		return;

	unsigned dlen = cdb_datalen(cdbm);
	char *chardata = malloc((size_t) dlen + 1);

	if (!chardata) {
		osec_error("malloc: %m");
		exit(EXIT_FAILURE);
	}

	if (cdb_read(cdbm, chardata, dlen, cdb_datapos(cdbm)) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_read(data)");

	chardata[dlen] = 0;

	dprintf(outfd, "%s=\"%s\"\n", name, chardata);

	free(chardata);
}

int main(int argc, char **argv)
{
	int c, fd, outfd, rc;
	size_t klen;
	char *dbfile, *outfile = NULL, *key;
	unsigned cpos, dlen;
	struct cdb cdbm;
	void *data;

	struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ 0, 0, 0, 0 }
	};

	while ((c = getopt_long(argc, argv, "hV", long_options, NULL)) != -1) {
		switch (c) {
			case 'V':
				print_version();
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if ((argc - optind) != 2)
		print_help(EXIT_FAILURE);

	dbfile = argv[optind++];
	outfile = argv[optind];

	// Open database
	if ((fd = open(dbfile, O_RDONLY | O_NOFOLLOW | O_NOCTTY)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", dbfile);

	if (!compat_db_version(fd))
		osec_fatal(EXIT_FAILURE, 0, "%s: file not look like osec database", dbfile);

	if (cdb_init(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(cdbm)");

	if ((outfd = open(outfile, O_WRONLY | O_CREAT | O_NOCTTY, S_IRUSR | S_IWUSR)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", outfile);

	print_meta(&cdbm, "hashnames", outfd);
	print_meta(&cdbm, "basepath", outfd);

	cdb_seqinit(&cpos, &cdbm);

	while ((rc = cdb_seqnext(&cpos, &cdbm)) > 0) {
		klen = cdb_keylen(&cdbm);
		key = malloc((size_t)(klen + 1));

		if (!key) {
			osec_error("malloc: %m");
			exit(EXIT_FAILURE);
		}

		if (cdb_read(&cdbm, key, (unsigned) klen, cdb_keypos(&cdbm)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read(key)");

		if (key[0] != '/') {
			free(key);
			continue;
		}

		key[klen] = '\0';

		dlen = cdb_datalen(&cdbm);
		data = malloc((size_t) dlen);

		if (!data) {
			osec_error("malloc: %m");
			exit(EXIT_FAILURE);
		}

		if (cdb_read(&cdbm, data, (unsigned) dlen, cdb_datapos(&cdbm)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read(data)");

		dump_record(outfd, key, data, dlen);

		free(data);
		free(key);
	}

	if (close(outfd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", outfile);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbfile);

	return EXIT_SUCCESS;
}
