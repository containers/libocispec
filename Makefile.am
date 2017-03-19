CLEANFILES = $(man_MANS)

AM_CFLAGS = $(WARN_CFLAGS)

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

noinst_LIBRARIES = libocispec.a

libocispec_a_SOURCES = src/spec.c

src/spec.c: runtime-spec/schema/config-schema.json src/generate.py
	(cd src; ./generate.py ../runtime-spec/schema/config-schema.json spec.h spec.c)

CLEANFILES += src/spec.h src/spec.c

tests_test_1_SOURCES = tests/test-1.c
tests_test_1_CFLAGS = -I$(builddir)/src
tests_test_1_LDADD = $(SELINUX_LIBS) $(YAJL_LIBS) libocispec.a

tests_test_2_SOURCES = tests/test-2.c
tests_test_2_CFLAGS = -I$(builddir)/src
tests_test_2_LDADD = $(SELINUX_LIBS) $(YAJL_LIBS) libocispec.a

bin_PROGRAMS = tests/test-1 tests/test-2

TESTS = tests/test-1 tests/test-2

-include $(top_srcdir)/git.mk

TEST_EXTENSIONS = .conf
CONF_LOG_COMPILER = $(top_srcdir)/tests/tests-runner

EXTRA_DIST = autogen.sh src/spec.c

EXTRA_DIST += $(TESTS:.conf=.conf.expected)
EXTRA_DIST += $(TESTS:.conf=.conf.command)
