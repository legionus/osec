WARNINGS = -Wall -Wextra -W -Wshadow -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization \
	\
	-Wno-pointer-arith

if USE_WERROR
WARNINGS += -Werror
endif

AM_CPPFLAGS = -g -std=c99 -D_GNU_SOURCE \
	-I$(srcdir)/../src \
	$(WARNINGS)

bin_PROGRAMS = osec-migrade-db
osec_migrade_db_SOURCES = updatedb.c \
	$(srcdir)/../src/common.c \
	$(srcdir)/../src/memory.c \
	$(srcdir)/../src/dbversion.c \
	$(srcdir)/../src/dbvalue.c \
	$(srcdir)/../src/hashtype.c

osec_migrade_db_LIBS = -lcdb -lgcrypt
