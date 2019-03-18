CLEANFILES = $(man_MANS)

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/src -I$(top_builddir)/src

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

noinst_LTLIBRARIES = libocispec.la
noinst_LIBRARIES = libocispec.a

SOURCE_FILES = src/oci_runtime_spec.c \
	src/oci_image_spec.c \
	src/oci_image_index_spec.c \
	src/oci_image_layout_spec.c \
	src/oci_image_manifest_spec.c \
	src/image_manifest_items.c \
	src/json_common.c

HEADER_FILES = $(SOURCE_FILES:.c=.h)

src/json_common.h src/json_common.c:
	$(PYTHON) $(srcdir)/src/generate.py

src/oci_runtime_spec.c: runtime-spec/schema/config-schema.json src/generate.py src/json_common.h
	$(PYTHON) $(srcdir)/src/generate.py $(srcdir)/runtime-spec/schema/config-schema.json src/oci_runtime_spec.h src/oci_runtime_spec.c oci_container $(OCI_RUNTIME_EXTENSIONS)

src/oci_image_spec.c: image-spec/schema/config-schema.json src/generate.py src/json_common.h
	$(PYTHON) $(srcdir)/src/generate.py $(srcdir)/image-spec/schema/config-schema.json src/oci_image_spec.h src/oci_image_spec.c oci_image $(OCI_IMAGE_EXTENSIONS)

src/oci_image_index_spec.c: image-spec/schema/image-index-schema.json src/generate.py src/json_common.h
	$(PYTHON) $(srcdir)/src/generate.py $(srcdir)/image-spec/schema/image-index-schema.json src/oci_image_index_spec.h src/oci_image_index_spec.c oci_image_index $(OCI_IMAGE_INDEX_EXTENSIONS)

src/oci_image_layout_spec.c: image-spec/schema/image-layout-schema.json src/generate.py src/json_common.h
	$(PYTHON) $(srcdir)/src/generate.py $(srcdir)/image-spec/schema/image-layout-schema.json src/oci_image_layout_spec.h src/oci_image_layout_spec.c oci_image_layout $(OCI_IMAGE_LAYOUT_EXTENSIONS)

src/oci_image_manifest_spec.c: image-spec/schema/image-manifest-schema.json src/generate.py src/json_common.h
	$(PYTHON) $(srcdir)/src/generate.py $(srcdir)/image-spec/schema/image-manifest-schema.json src/oci_image_manifest_spec.h src/oci_image_manifest_spec.c oci_image_manifest $(OCI_IMAGE_MANIFEST_EXTENSIONS)

src/image_manifest_items.c: tests/test-spec/imageManifestItems/image-manifest-items-schema.json src/generate.py src/json_common.h
	$(PYTHON) $(srcdir)/src/generate.py $(srcdir)/tests/test-spec/imageManifestItems/image-manifest-items-schema.json src/image_manifest_items.h src/image_manifest_items.c image_manifest_items $(OCI_IMAGE_MANIFEST_ITEMS_EXTENSIONS)

$(HEADER_FILES): %.h: %.c src/generate.py

BUILT_SOURCES = $(HEADER_FILES) $(SOURCE_FILES)

libocispec_la_SOURCES = $(SOURCE_FILES) \
	src/read-file.c

libocispec_a_SOURCES =

CLEANFILES += $(HEADER_FILES) $(SOURCE_FILES)

TESTS_LDADD = libocispec.la $(SELINUX_LIBS) $(YAJL_LIBS)

libocispec.a: libocispec.la
	$(LIBTOOL) --mode=link $(GCC) libocispec.la -o libocispec.a

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

tests_test_8_SOURCES = tests/test-8.c
tests_test_8_LDADD = $(TESTS_LDADD)

src_validate_SOURCES = src/validate.c
src_validate_LDADD = $(TESTS_LDADD)

TESTS = tests/test-1 \
	tests/test-2 \
	tests/test-3 \
	tests/test-4 \
	tests/test-5 \
	tests/test-6 \
	tests/test-7 \
	tests/test-8

noinst_PROGRAMS = src/validate $(TESTS)

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
	tests/data/image_manifest_item.json \
	tests/test-spec \
	src/generate.py \
	$(HEADER_FILES) \
	src/read-file.h \
	src/json_common.h \
	runtime-spec \
	image-spec

sync:
	(cd image-spec; git pull https://github.com/opencontainers/image-spec)
	(cd runtime-spec; git pull https://github.com/opencontainers/runtime-spec)
