WARNINGS = -Wall -Wextra -W -Wshadow -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization \
	\
	-Wno-pointer-arith

if USE_WERROR
WARNINGS += -Werror
endif

AM_CPPFLAGS = -g -std=c99 -D_BSD_SOURCE -D_GNU_SOURCE -I../src -I../src/block-sha1 \
	$(WARNINGS)

bin_PROGRAMS = osec-migrade-db
osec_migrade_db_SOURCES = updatedb.c ../src/common.c ../src/memory.c \
	../src/dbversion.c ../src/dbvalue.c ../src/digest.c \
	../src/block-sha1/sha1.c

osec_migrade_db_LIBS = -lcdb
