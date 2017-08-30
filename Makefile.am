CLEANFILES = $(man_MANS)

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/src -I$(top_builddir)/src

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

noinst_LIBRARIES = libocispec.a

SOURCE_FILES = src/oci_runtime_spec.c \
	src/oci_image_spec.c \
	src/oci_image_index_spec.c \
	src/oci_image_layout_spec.c \
	src/oci_image_manifest_spec.c \
	src/oci_json_common.c

HEADER_FILES = $(SOURCE_FILES:.c=.h)

src/oci_runtime_spec.c: runtime-spec/schema/config-schema.json src/generate.py
	$(srcdir)/src/generate.py $(srcdir)/runtime-spec/schema/config-schema.json src/oci_runtime_spec.h src/oci_runtime_spec.c container

src/oci_image_spec.c: image-spec/schema/config-schema.json src/generate.py
	$(srcdir)/src/generate.py $(srcdir)/image-spec/schema/config-schema.json src/oci_image_spec.h src/oci_image_spec.c image

src/oci_image_index_spec.c: image-spec/schema/image-index-schema.json src/generate.py
	$(srcdir)/src/generate.py $(srcdir)/image-spec/schema/image-index-schema.json src/oci_image_index_spec.h src/oci_image_index_spec.c image_index

src/oci_image_layout_spec.c: image-spec/schema/image-layout-schema.json src/generate.py
	$(srcdir)/src/generate.py $(srcdir)/image-spec/schema/image-layout-schema.json src/oci_image_layout_spec.h src/oci_image_layout_spec.c image_layout

src/oci_image_manifest_spec.c: image-spec/schema/image-manifest-schema.json src/generate.py
	$(srcdir)/src/generate.py $(srcdir)/image-spec/schema/image-manifest-schema.json src/oci_image_manifest_spec.h src/oci_image_manifest_spec.c image_manifest

$(HEADER_FILES): %.h: %.c src/generate.py

BUILT_SOURCES = $(HEADER_FILES) $(SOURCE_FILES)

libocispec_a_SOURCES = $(SOURCE_FILES) \
	src/read-file.c

CLEANFILES += $(HEADER_FILES) $(SOURCE_FILES)

TESTS_LDADD = libocispec.a $(SELINUX_LIBS) $(YAJL_LIBS)

tests_test_1_SOURCES = tests/test-1.c
tests_test_1_LDADD = $(TESTS_LDADD)

tests_test_2_SOURCES = tests/test-2.c
tests_test_2_LDADD = $(TESTS_LDADD)

tests_test_3_SOURCES = tests/test-3.c
tests_test_3_LDADD = $(TESTS_LDADD)

tests_test_4_SOURCES = tests/test-4.c
tests_test_4_LDADD = $(TESTS_LDADD)

tests_test_5_SOURCES = tests/test-5.c
tests_test_5_LDADD = $(TESTS_LDADD)

tests_test_6_SOURCES = tests/test-6.c
tests_test_6_LDADD = $(TESTS_LDADD)

tests_test_7_SOURCES = tests/test-7.c
tests_test_7_LDADD = $(TESTS_LDADD)

src_validate_SOURCES = src/validate.c
src_validate_LDADD = $(TESTS_LDADD)

TESTS = tests/test-1 \
	tests/test-2 \
	tests/test-3 \
	tests/test-4 \
	tests/test-5 \
	tests/test-6 \
	tests/test-7

bin_PROGRAMS = src/validate $(TESTS)

$(abs_top_builddir)/tests/data: $(abs_top_srcdir)/tests/data
	if test $(abs_top_srcdir) != $(abs_top_builddir) && test ! -d $@; then rm -f $@; ln -s $< $@; fi

distcheck check: $(abs_top_builddir)/tests/data

-include $(top_srcdir)/git.mk

EXTRA_DIST = autogen.sh \
	tests/data/image_index_config.json \
	tests/data/image_layout_config.json \
	tests/data/image_config_mapstringobject.json \
	tests/data/config.json \
	tests/data/image_manifest.json \
	tests/data/image_config.json \
	tests/data/config.nocwd.json \
	src/generate.py \
	$(HEADER_FILES) \
	src/read-file.h \
	src/oci_json_common.h \
	runtime-spec \
	image-spec
