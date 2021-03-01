AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/src -I$(top_builddir)/src

CLEANFILES = $(man_MANS) src/runtime_spec_stamp src/image_spec_stamp src/image_manifest_stamp src/basic-test_stamp

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

noinst_LTLIBRARIES = libocispec.la
noinst_LIBRARIES = libocispec.a

SOURCE_FILES = \
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
	src/basic_test_double_array_item.c \
	src/basic_test_double_array.c \
	src/basic_test_top_array_int.c \
	src/basic_test_top_array_string.c \
	src/basic_test_top_double_array_int.c \
	src/basic_test_top_double_array_obj.c \
	src/basic_test_top_double_array_refobj.c \
	src/basic_test_top_double_array_string.c

HEADER_FILES = $(SOURCE_FILES:.c=.h)

src/runtime_spec_stamp: src/json_common.h src/json_common.c
	$(PYTHON) $(srcdir)/src/generate.py --gen-ref --root=${srcdir} --out=${builddir}/src ${srcdir}/runtime-spec/schema
	@touch $@

src/image_spec_stamp: src/json_common.h src/json_common.c
	$(PYTHON) $(srcdir)/src/generate.py --gen-ref --root=${srcdir} --out=${builddir}/src ${srcdir}/image-spec/schema
	@touch $@

src/image_manifest_stamp: src/json_common.h src/json_common.c
	$(PYTHON) $(srcdir)/src/generate.py --gen-ref --root=${srcdir}/tests/test-spec --out=${builddir}/src ${srcdir}/tests/test-spec/imageManifestItems
	@touch $@

src/basic-test_stamp: src/json_common.h src/json_common.c
	$(PYTHON) $(srcdir)/src/generate.py --gen-ref --root=${srcdir}/tests/test-spec --out=${builddir}/src ${srcdir}/tests/test-spec/basic
	@touch $@

src/image_spec_schema_config_schema.c \
	src/image_spec_schema_content_descriptor.c \
	src/image_spec_schema_defs.c \
	src/image_spec_schema_defs_descriptor.c \
	src/image_spec_schema_image_index_schema.c \
	src/image_spec_schema_image_layout_schema.c \
	src/image_spec_schema_image_manifest_schema.c \
	src/image_spec_schema_config_schema.h \
	src/image_spec_schema_content_descriptor.h \
	src/image_spec_schema_defs.h \
	src/image_spec_schema_defs_descriptor.h \
	src/image_spec_schema_image_index_schema.h \
	src/image_spec_schema_image_layout_schema.h \
	src/image_spec_schema_image_manifest_schema.h: src/image_spec_stamp

src/runtime_spec_schema_config_linux.h \
	src/runtime_spec_schema_config_schema.h \
	src/runtime_spec_schema_config_solaris.h \
	src/runtime_spec_schema_config_vm.h \
	src/runtime_spec_schema_config_windows.h \
	src/runtime_spec_schema_defs.h \
	src/runtime_spec_schema_defs_linux.h \
	src/runtime_spec_schema_defs_vm.h \
	src/runtime_spec_schema_defs_windows.h \
	src/runtime_spec_schema_state_schema.h \
	src/runtime_spec_schema_config_linux.c \
	src/runtime_spec_schema_config_schema.c \
	src/runtime_spec_schema_config_solaris.c \
	src/runtime_spec_schema_config_vm.c \
	src/runtime_spec_schema_config_windows.c \
	src/runtime_spec_schema_defs.c \
	src/runtime_spec_schema_defs_linux.c \
	src/runtime_spec_schema_defs_vm.c \
	src/runtime_spec_schema_defs_windows.c \
	src/runtime_spec_schema_state_schema.c: src/runtime_spec_stamp

src/image_manifest_items_image_manifest_items_schema.h \
	src/image_manifest_items_image_manifest_items_schema.c: src/image_manifest_stamp

src/basic_test_double_array_item.h \
	src/basic_test_double_array.h \
	src/basic_test_top_array_int.h \
	src/basic_test_top_array_string.h \
	src/basic_test_top_double_array_int.h \
	src/basic_test_top_double_array_obj.h \
	src/basic_test_top_double_array_refobj.h \
	src/basic_test_top_double_array_string.h \
	src/basic_test_double_array_item.c \
	src/basic_test_double_array.c \
	src/basic_test_top_array_int.c \
	src/basic_test_top_array_string.c \
	src/basic_test_top_double_array_int.c \
	src/basic_test_top_double_array_obj.c \
	src/basic_test_top_double_array_refobj.c \
	src/basic_test_top_double_array_string.c: src/basic-test_stamp

$(HEADER_FILES): %.h: %.c src/generate.py

BUILT_SOURCES = $(HEADER_FILES) $(SOURCE_FILES)

libocispec_a_SOURCES =

libocispec_la_SOURCES = $(BUILT_SOURCES) \
	src/read-file.c \
	src/json_common.c

TMP_C_FILES = $(HEADER_FILES:.h=.h.tmp)
TMP_C_FILES = $(SOURCE_FILES:.c=.c.tmp)

CLEANFILES += $(HEADER_FILES) $(SOURCE_FILES) $(TMP_H_FILES) $(TMP_C_FILES)

TESTS_LDADD = libocispec.la $(SELINUX_LIBS) $(YAJL_LIBS)

libocispec.a: libocispec.la $(BUILT_SOURCES) src/runtime_spec_stamp src/image_spec_stamp src/image_manifest_stamp src/basic-test_stamp
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

tests_test_9_SOURCES = tests/test-9.c
tests_test_9_LDADD = $(TESTS_LDADD)

tests_test_10_SOURCES = tests/test-10.c
tests_test_10_LDADD = $(TESTS_LDADD)

src_validate_SOURCES = src/validate.c
src_validate_LDADD = $(TESTS_LDADD)

TESTS = tests/test-1 \
	tests/test-2 \
	tests/test-3 \
	tests/test-4 \
	tests/test-5 \
	tests/test-6 \
	tests/test-7 \
	tests/test-8 \
	tests/test-9 \
	tests/test-10

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
	tests/data/residual_image_layout_config.json \
	tests/data/doublearray.json \
	tests/data/top_array_int.json \
	tests/data/top_array_string.json \
	tests/data/top_double_array_int.json \
	tests/data/top_double_array_obj.json \
	tests/data/top_double_array_refobj.json \
	tests/data/top_double_array_string.json \
	tests/test-spec \
	src/generate.py \
	src/headers.py \
	src/helpers.py \
	src/sources.py \
	$(HEADER_FILES) \
	src/read-file.h \
	src/json_common.h \
	runtime-spec \
	image-spec \
	src/json_common.h \
	src/json_common.c

sync:
	(cd image-spec; git pull https://github.com/opencontainers/image-spec)
	(cd runtime-spec; git pull https://github.com/opencontainers/runtime-spec)

generate: src/runtime_spec_stamp src/image_spec_stamp src/image_manifest_stamp src/basic-test_stamp
