CLEANFILES = $(man_MANS)

AM_CFLAGS = $(WARN_CFLAGS)

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

noinst_LIBRARIES = libocispec.a

libocispec_a_SOURCES = src/oci_runtime_spec.c src/read-file.c \
			src/oci_image_spec.c \
			src/oci_image_index_spec.c \
			src/oci_image_layout_spec.c \
			src/oci_image_manifest_spec.c

src/oci_runtime_spec.c: runtime-spec/schema/config-schema.json src/generate.py
	(cd src; ./generate.py ../runtime-spec/schema/config-schema.json oci_runtime_spec.h oci_runtime_spec.c container)

src/oci_runtime_spec.h: src/oci_runtime_spec.c


src/oci_image_spec.c: image-spec/schema/config-schema.json src/generate.py
	(cd src; ./generate.py ../image-spec/schema/config-schema.json oci_image_spec.h oci_image_spec.c image)

src/oci_image_spec.h: src/oci_image_spec.c


src/oci_image_index_spec.c: image-spec/schema/image-index-schema.json src/generate.py
	(cd src; ./generate.py ../image-spec/schema/image-index-schema.json oci_image_index_spec.h oci_image_index_spec.c image_index)

src/oci_image_index_spec.h: src/oci_image_index_spec.c


src/oci_image_layout_spec.c: image-spec/schema/image-layout-schema.json src/generate.py
	(cd src; ./generate.py ../image-spec/schema/image-layout-schema.json oci_image_layout_spec.h oci_image_layout_spec.c image_layout)

src/oci_image_layout_spec.h: src/oci_image_layout_spec.c

src/oci_image_manifest_spec.c: image-spec/schema/image-manifest-schema.json src/generate.py
	(cd src; ./generate.py ../image-spec/schema/image-manifest-schema.json oci_image_manifest_spec.h oci_image_manifest_spec.c image_manifest)

src/oci_image_manifest_spec.h: src/oci_image_manifest_spec.c

CLEANFILES += src/oci_runtime_spec.h src/oci_runtime_spec.c \
		src/oci_image_spec.h src/oci_image_spec.c \
		src/oci_image_index_spec.h src/oci_image_index_spec.c \
		src/oci_image_layout_spec.h src/oci_image_layout_spec.c \
		src/oci_image_manifest_spec.h src/oci_image_manifest_spec.c

tests_test_1_SOURCES = tests/test-1.c
tests_test_1_CFLAGS = -I$(builddir)/src
tests_test_1_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_2_SOURCES = tests/test-2.c
tests_test_2_CFLAGS = -I$(builddir)/src
tests_test_2_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_3_SOURCES = tests/test-3.c
tests_test_3_CFLAGS = -I$(builddir)/src
tests_test_3_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_4_SOURCES = tests/test-4.c
tests_test_4_CFLAGS = -I$(builddir)/src
tests_test_4_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_5_SOURCES = tests/test-5.c
tests_test_5_CFLAGS = -I$(builddir)/src
tests_test_5_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_6_SOURCES = tests/test-6.c
tests_test_6_CFLAGS = -I$(builddir)/src
tests_test_6_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_7_SOURCES = tests/test-7.c
tests_test_7_CFLAGS = -I$(builddir)/src
tests_test_7_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

src_validate_SOURCES = src/validate.c
src_validate_CFLAGS = -I$(builddir)/src
src_validate_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

bin_PROGRAMS = src/validate tests/test-1 tests/test-2 tests/test-3 \
		tests/test-4 \
		tests/test-5 \
		tests/test-6 \
		tests/test-7

TESTS = tests/test-1 tests/test-2 tests/test-3 tests/test-4 \
		tests/test-5	\
		tests/test-6	\
		tests/test-7

-include $(top_srcdir)/git.mk

TEST_EXTENSIONS = .conf
CONF_LOG_COMPILER = $(top_srcdir)/tests/tests-runner

EXTRA_DIST = autogen.sh src/oci_runtime_spec.h src/read-file.h \
		src/oci_image_spec.h \
		src/oci_image_index_spec.h

EXTRA_DIST += $(TESTS:.conf=.conf.expected)
EXTRA_DIST += $(TESTS:.conf=.conf.command)
