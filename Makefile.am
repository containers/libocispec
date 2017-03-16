CLEANFILES = $(man_MANS)

AM_CFLAGS = $(WARN_CFLAGS)

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

bin_PROGRAMS = crun

src/spec.c: runtime-spec/schema/config-schema.json
	(cd src; ./generate.py ../runtime-spec/schema/config-schema.json spec.h spec.c)

crun_SOURCES = \
	src/spec.c \
	src/crun.c \
	src/container.c \
	src/linux_container.c \
	src/safe-read-write.c \
	$(NULL)

crun_CFLAGS = $(AM_CFLAGS) $(JSON_GLIB_CFLAGS) $(GIO_UNIX_CFLAGS)
crun_LDADD = $(SELINUX_LIBS) $(JSON_GLIB_LIBS) $(GIO_UNIX_LIBS)

-include $(top_srcdir)/git.mk

TEST_EXTENSIONS = .conf
CONF_LOG_COMPILER = $(top_srcdir)/tests/tests-runner

EXTRA_DIST = autogen.sh src/safe-read-write.h src/container.h src/linux_container.h src/spec.c

EXTRA_DIST += $(TESTS:.conf=.conf.expected)
EXTRA_DIST += $(TESTS:.conf=.conf.command)
