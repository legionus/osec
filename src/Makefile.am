HELP2MAN = help2man -N -s1 -S '$(PACKAGE_STRING)'

WARNINGS = -Wall -Wextra -Werror -W -Wshadow -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization \
	\
	-Wno-pointer-arith

AM_CPPFLAGS = -g -std=c99 -D_BSD_SOURCE -D_GNU_SOURCE \
	$(WARNINGS)

AM_CPPFLAGS += -I./mozilla-sha1

bin_PROGRAMS = osec osec2txt txt2osec
osec_SOURCES = osec.c common.c memory.c privs.c status.c digest.c dbvalue.c \
		dbversion.c exclude.c ignore.c path.c \
		./mozilla-sha1/sha1.c
osec_LIBS = -lcap -lcdb
dist_man_MANS = osec.1 osec2txt.1 txt2osec.1

osec2txt_SOURCES = osec2txt.c
osec2txt_LDADD = common.o memory.o dbvalue.o dbversion.o digest.o sha1.o
osec2txt_LIBS = -lcdb

txt2osec_SOURCES = txt2osec.c
txt2osec_LDADD = common.o memory.o dbvalue.o digest.o sha1.o dbversion.o
txt2osec_LIBS = -lcdb

%.1: % %.1.inc
	$(HELP2MAN) -i $@.inc ./$< >$@
