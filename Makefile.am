CLEANFILES = $(man_MANS)

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/src -I$(top_builddir)/src

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

noinst_LTLIBRARIES = libocispec.la
noinst_LIBRARIES = libocispec.a

SOURCE_FILES = src/json_common.c \
	src/image_spec_schema_config_schema.c \
	src/image_spec_schema_content_descriptor.c \
	src/image_spec_schema_defs.c \
	src/image_spec_schema_defs_descriptor.c \
	src/image_spec_schema_image_index_schema.c \
	src/image_spec_schema_image_layout_schema.c \
	src/image_spec_schema_image_manifest_schema.c \
	src/runtime_spec_schema_config_linux.c \
	src/runtime_spec_schema_config_schema.c \
	src/runtime_spec_schema_config_solaris.c \
	src/runtime_spec_schema_config_vm.c \
	src/runtime_spec_schema_config_windows.c \
	src/runtime_spec_schema_defs.c \
	src/runtime_spec_schema_defs_linux.c \
	src/runtime_spec_schema_defs_vm.c \
	src/runtime_spec_schema_defs_windows.c \
	src/runtime_spec_schema_state_schema.c \
	src/image_manifest_items_image_manifest_items_schema.c \
	src/json_common.c

HEADER_FILES = $(SOURCE_FILES:.c=.h)

src/json_common.h src/json_common.c:
	$(PYTHON) $(srcdir)/src/generate.py --gen-common --gen-ref --root=${srcdir} --out=${srcdir}/src ${srcdir}/runtime-spec/schema ${srcdir}/image-spec/schema
	$(PYTHON) $(srcdir)/src/generate.py --gen-common --gen-ref --root=${srcdir}/tests/test-spec --out=${srcdir}/src ${srcdir}/tests/test-spec/imageManifestItems


src/image_spec_schema_config_schema.c \
	src/image_spec_schema_content_descriptor.c \
	src/image_spec_schema_defs.c \
	src/image_spec_schema_defs_descriptor.c \
	src/image_spec_schema_image_index_schema.c \
	src/image_spec_schema_image_layout_schema.c \
	src/image_spec_schema_image_manifest_schema.c \
	src/runtime_spec_schema_config_linux.c \
	src/runtime_spec_schema_config_schema.c \
	src/runtime_spec_schema_config_solaris.c \
	src/runtime_spec_schema_config_vm.c \
	src/runtime_spec_schema_config_windows.c \
	src/runtime_spec_schema_defs.c \
	src/runtime_spec_schema_defs_linux.c \
	src/runtime_spec_schema_defs_vm.c \
	src/runtime_spec_schema_defs_windows.c \
	src/runtime_spec_schema_state_schema.c \
	src/image_manifest_items_image_manifest_items_schema.c: src/json_common.h

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
	src/common_c.py \
	src/common_h.py \
	src/headers.py \
	src/helpers.py \
	src/sources.py \
	$(HEADER_FILES) \
	src/read-file.h \
	src/json_common.h \
	runtime-spec \
	image-spec

sync:
	(cd image-spec; git pull https://github.com/opencontainers/image-spec)
	(cd runtime-spec; git pull https://github.com/opencontainers/runtime-spec)
generate:
	$(PYTHON) $(srcdir)/src/generate.py --gen-common --gen-ref --root=${srcdir} --out=${srcdir}/src ${srcdir}/runtime-spec/schema ${srcdir}/image-spec/schema
	$(PYTHON) $(srcdir)/src/generate.py --gen-common --gen-ref --root=${srcdir}/tests/test-spec --out=${srcdir}/src ${srcdir}/tests/test-spec/imageManifestItems
