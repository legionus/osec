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
#include <cdb.h>

#include "config.h"
#include "osec.h"

// FIXME: use config file for this variables.
char def_db_path[] = "/tmp/osec";
char def_user[]    = "osec";
char def_group[]   = "osec";

char *db_path = NULL;
int read_only = 0;
int numeric_user_group = 0;

static void __attribute__ ((noreturn))
print_help(int ret)  {
	printf("Usage: %s [OPTIONS]\n\n"
	       "Options:\n"
	       "  -r, --read-only     work in read-only mode\n"
	       "  -R, --allow-root    allow run with root priveleges\n"
	       "  -n, --numeric-ids   dont convert uid/gid into username\n"
	       "  -u, --user          non-privelege user account name\n"
	       "  -g, --group         non-privelege group account name\n"
	       "  -D, --dbpath        path to the directory with databases\n"
	       "  -f, --file          obtain directories from file FILE\n"
	       "  -V, --version       print program version and exit.\n"
	       "  -h, --help          output a brief help message.\n\n",
	       PACKAGE_NAME);
	exit(ret);
}

static void __attribute__ ((noreturn))
print_version(void) {
        printf("%s version %s\n\n", PACKAGE_NAME, PACKAGE_VERSION);
        exit(EXIT_SUCCESS);
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

static int
osec_append(struct cdb_make *cdbm, char *fname, size_t flen) {
	DIR *d;
	int retval = 1;
	struct dirent *dir;
	struct osec_stat ost;
	struct stat st;

	if (lstat(fname, &st) == -1) {
		retval = osec_error("%s: lstat: %s\n", fname, strerror(errno));
		return retval;
	}

	ost.uid = st.st_uid;
	ost.gid = st.st_gid;
	ost.mode = st.st_mode;

	if (S_ISREG(st.st_mode))
		digest(fname, &ost);
	else
		bzero(ost.digest, digest_len);

	if (cdb_make_add(cdbm, fname, flen, &ost, sizeof(ost)) != 0)
		osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fname);

	if (!S_ISDIR(st.st_mode))
		return retval;

	if ((d = opendir(fname)) == NULL) {
		if (errno == EACCES) {
			osec_error("%s: opendir: %s\n", fname, strerror(errno));
			return retval;
		}
		else
			osec_fatal(EXIT_FAILURE, errno, "%s: opendir", fname);
	}

	while ((dir = readdir(d)) != NULL) {
		char *subname;
		size_t len = strlen(dir->d_name);

		if ((len <= 2) &&
		    (!strncmp(dir->d_name, "..", 2) || !strncmp(dir->d_name, ".", 1)))
			continue;

		len += flen + 1;

		subname = (char *) xmalloc(sizeof(char) * len);
		sprintf(subname, "%s/%s", fname, dir->d_name);

		retval = osec_append(cdbm, subname, len);
		xfree(subname);

		if (!retval)
			break;
	}

	if (closedir(d) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: closedir", fname);

	return retval;
}

static int
create_database(int fd, char *dir, size_t len) {
	struct cdb_make cdbm;
	int retval = 1;

	if (cdb_make_start(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	retval = osec_append(&cdbm, dir, len);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	return retval;
}

static void
show_changes(int new_fd, int old_fd) {
	char *key;
	unsigned cpos, klen;
	struct cdb old_cdb, new_cdb;
	struct osec_stat new_st, old_st;
	size_t datalen = sizeof(struct osec_stat);

	if (old_fd != -1 && cdb_init(&old_cdb, old_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(old_cdb)");

	if (cdb_init(&new_cdb, new_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(new_cdb)");

	cdb_seqinit(&cpos, &new_cdb);
	while(cdb_seqnext(&cpos, &new_cdb) > 0) {
		klen = cdb_keylen(&new_cdb);
		key = (char *) xmalloc(klen + 1);

		if (cdb_read(&new_cdb, key, klen, cdb_keypos(&new_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		key[klen] = '\0';

		if (cdb_read(&new_cdb, &new_st, datalen, cdb_datapos(&new_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		// Search
		if (old_fd != -1 && cdb_find(&old_cdb, key, klen) > 0) {
			if (cdb_read(&old_cdb, &old_st, datalen, cdb_datapos(&old_cdb)) < 0)
				osec_fatal(EXIT_FAILURE, errno, "cdb_read");

			if (!check_difference(key, &new_st, &old_st))
				check_bad_files(key, &new_st);
		}
		else
			check_new(key, &new_st);

		xfree(key);
	}
}

static void
show_oldfiles(int new_fd, int old_fd) {
	char *key;
	unsigned cpos, klen;
	struct cdb old_cdb, new_cdb;
	struct osec_stat old_st;
	size_t datalen = sizeof(struct osec_stat);

	if (old_fd == -1)
		return;

	if (cdb_init(&old_cdb, old_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(old_cdb)");

	if (cdb_init(&new_cdb, new_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(new_cdb)");

	cdb_seqinit(&cpos, &old_cdb);
	while(cdb_seqnext(&cpos, &old_cdb) > 0) {
		klen = cdb_keylen(&old_cdb);
		key = (char *) xmalloc(klen + 1);

		if (cdb_read(&old_cdb, key, klen, cdb_keypos(&old_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		key[klen] = '\0';

		if (cdb_read(&old_cdb, &old_st, datalen, cdb_datapos(&old_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		if (cdb_find(&new_cdb, key, klen) == 0)
			check_removed(key, &old_st);

		xfree(key);
	}
}

static int
process(char *dirname, size_t dlen) {
	size_t len;
	int retval = 1;
	int new_fd, old_fd;
	char *new_dbname, *old_dbname;

	// Generate priv state database name
	gen_db_name(dirname, &old_dbname);

	// Open old database
	errno = 0;
	if ((old_fd = open(old_dbname, O_RDONLY|O_NOCTTY|O_NOFOLLOW)) != -1)
		printf("Processing %s ...\n", dirname);
	else if (errno == ENOENT)
		printf("Init database for %s ...\n", dirname);
	else
		osec_fatal(EXIT_FAILURE, errno, "%s: open", old_dbname);

	// Generate new state database
	len = strlen(db_path) + 16;
	new_dbname = (char *) xmalloc(sizeof(char) * len);
	sprintf(new_dbname, "%s/osec.XXXXXXXXX", db_path);

	// Open new database
	if ((new_fd = mkstemp(new_dbname)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkstemp", new_dbname);

	// Unlink termporary file
	if (read_only)
		remove(new_dbname);

	// Create new state
	if (create_database(new_fd, dirname, dlen)) {
		show_changes(new_fd, old_fd);
		show_oldfiles(new_fd, old_fd);
	}
	else
		retval = osec_error("Unable to create database\n");

	if (old_fd != -1 && close(old_fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", old_dbname);

	if (close(new_fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", new_dbname);

	//replace database with new
	if (retval && !read_only) {
		chmod(new_dbname, S_IRUSR|S_IWUSR|S_IRGRP);
		rename(new_dbname, old_dbname);
	}

	xfree(old_dbname);
	xfree(new_dbname);

	return retval;
}

static char *
validate_path(const char *path) {
	unsigned int i, j = 0;
	char *buf = NULL;
	size_t len;

	len = strlen(path);

	if (path[0] != '/' ||
	    strstr(path, "/../") != NULL ||
	    strstr(path, "/./" ) != NULL) {
		osec_error("Canonical path required\n");
		return buf;
	}

	buf = (char *) malloc(sizeof(char) * (len+1));
	buf[j++] = '/';

	for(i = 1; i < len; i++) {
		if (path[i-1] == '/' && path[i] == '/')
			continue;
		buf[j++] = path[i];
	}
	buf[j] = '\0';

	if (buf[j-1] == '/')
		buf[j-1] = '\0';

	if (j < len)
		buf = realloc(buf, sizeof(char) * j);

	return buf;
}


int
main(int argc, char **argv) {
	int c;
	int retval = EXIT_SUCCESS;
	int allow_root = 0;
	char *dirslist_file = NULL;
	char *user = NULL, *group = NULL;

	char *path;
	size_t path_len;

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'v' },
		{ "read-only",		no_argument,		0, 'r' },
		{ "allow-root",		no_argument,		0, 'R' },
		{ "numeric-ids",	no_argument,		0, 'n' },
		{ "dbpath",		required_argument,	0, 'D' },
		{ "file",		required_argument,	0, 'f' },
		{ "user",		required_argument,	0, 'u' },
		{ "group",		required_argument,	0, 'g' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long (argc, argv, "hvnrRu:g:D:f:", long_options, NULL)) != -1) {
		switch (c) {
			case 'V':
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
			case 'D':
				db_path = optarg;
				break;
			case 'f':
				dirslist_file = optarg;
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
	if (!allow_root && !geteuid())
		drop_privs((user  != NULL ? user  : def_user),
			   (group != NULL ? group : def_group));

	if (dirslist_file != NULL) {
		FILE *fd;
		char *line = NULL;
		size_t len = 0;
		ssize_t n;

		if ((fd = fopen(dirslist_file, "r")) == NULL) {
			osec_fatal(EXIT_FAILURE, errno, "%s: fopen", dirslist_file);
		}

		while ((n = getline(&line, &len, fd)) != -1) {
			int i = 0;

			while(isspace(line[i]))
				i++;

			if (strlen((line + i)) == 0 || line[i] == '#')
				continue;

			if (line[n-1] == '\n')
				line[n-1] = '\0';

			if ((path = validate_path((line + i))) == NULL)
				continue;

			path_len = strlen(path) + 1;

			if (process(path, path_len))
				retval = EXIT_FAILURE;

			xfree(path);
		}

		xfree(line);

		if (fclose(fd) != 0)
			osec_fatal(EXIT_FAILURE, errno, "%s: fclose", dirslist_file);
	}

	while (optind < argc) {
		if ((path = validate_path(argv[optind++])) == NULL)
			continue;

		path_len = strlen(path) + 1;

		if (!process(path, path_len))
			retval = EXIT_FAILURE;

		xfree(path);
	}

	return retval;
}
