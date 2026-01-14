DIST_SUBDIRS = yajl
SUBDIRS = yajl

AM_CFLAGS = $(WARN_CFLAGS) -I$(top_srcdir)/src -I$(top_builddir)/src

if HAVE_EMBEDDED_YAJL
AM_CFLAGS += -I$(top_srcdir)/yajl/src/headers
endif HAVE_EMBEDDED_YAJL

CLEANFILES = $(man_MANS) src/runtime_spec_stamp src/image_spec_stamp src/image_manifest_stamp src/basic-test_stamp

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4


if ENABLE_LIBOCISPEC_INSTALL
lib_LTLIBRARIES = libocispec.la
lib_LIBRARIES = libocispec.a
else
noinst_LTLIBRARIES = libocispec.la
noinst_LIBRARIES = libocispec.a
endif

SOURCE_FILES =							\
	src/ocispec/image_spec_schema_config_schema.c		\
	src/ocispec/image_spec_schema_content_descriptor.c	\
	src/ocispec/image_spec_schema_defs.c			\
	src/ocispec/image_spec_schema_defs_descriptor.c		\
	src/ocispec/image_spec_schema_image_index_schema.c	\
	src/ocispec/image_spec_schema_image_layout_schema.c	\
	src/ocispec/image_spec_schema_image_manifest_schema.c	\
	src/ocispec/runtime_spec_schema_config_freebsd.c \
	src/ocispec/runtime_spec_schema_config_linux.c \
	src/ocispec/runtime_spec_schema_config_zos.c \
	src/ocispec/runtime_spec_schema_config_schema.c \
	src/ocispec/runtime_spec_schema_config_solaris.c \
	src/ocispec/runtime_spec_schema_config_vm.c \
	src/ocispec/runtime_spec_schema_config_windows.c \
	src/ocispec/runtime_spec_schema_defs.c \
	src/ocispec/runtime_spec_schema_defs_freebsd.c \
	src/ocispec/runtime_spec_schema_defs_linux.c \
	src/ocispec/runtime_spec_schema_defs_zos.c \
	src/ocispec/runtime_spec_schema_defs_vm.c \
	src/ocispec/runtime_spec_schema_defs_windows.c \
	src/ocispec/runtime_spec_schema_state_schema.c \
	src/ocispec/runtime_spec_schema_features_linux.c \
	src/ocispec/runtime_spec_schema_features_schema.c \
	src/ocispec/image_manifest_items_image_manifest_items_schema.c \
	src/ocispec/basic_test_double_array_item.c \
	src/ocispec/basic_test_double_array.c \
	src/ocispec/basic_test_top_array_int.c \
	src/ocispec/basic_test_top_array_string.c \
	src/ocispec/basic_test_top_double_array_int.c \
	src/ocispec/basic_test_top_double_array_obj.c \
	src/ocispec/basic_test_top_double_array_refobj.c \
	src/ocispec/basic_test_top_double_array_string.c

HEADER_FILES = $(SOURCE_FILES:.c=.h)

if ENABLE_LIBOCISPEC_INSTALL
ocispec_includedir = $(includedir)/ocispec
ocispec_include_HEADERS = $(HEADER_FILES) \
                          src/ocispec/json_common.h \
                          src/ocispec/read-file.h
endif

src/runtime_spec_stamp: src/ocispec/json_common.h src/ocispec/json_common.c
	$(PYTHON) $(srcdir)/src/ocispec/generate.py --gen-ref --root=${srcdir} --out=${builddir}/src/ocispec ${srcdir}/runtime-spec/schema
	@touch $@

src/image_spec_stamp: src/ocispec/json_common.h src/ocispec/json_common.c
	$(PYTHON) $(srcdir)/src/ocispec/generate.py --gen-ref --root=${srcdir} --out=${builddir}/src/ocispec ${srcdir}/image-spec/schema
	@touch $@

src/image_manifest_stamp: src/ocispec/json_common.h src/ocispec/json_common.c
	$(PYTHON) $(srcdir)/src/ocispec/generate.py --gen-ref --root=${srcdir}/tests/test-spec --out=${builddir}/src/ocispec ${srcdir}/tests/test-spec/imageManifestItems
	@touch $@

src/basic-test_stamp: src/ocispec/json_common.h src/ocispec/json_common.c
	$(PYTHON) $(srcdir)/src/ocispec/generate.py --gen-ref --root=${srcdir}/tests/test-spec --out=${builddir}/src/ocispec ${srcdir}/tests/test-spec/basic
	@touch $@

src/ocispec/image_spec_schema_config_schema.c \
	src/ocispec/image_spec_schema_content_descriptor.c \
	src/ocispec/image_spec_schema_defs.c \
	src/ocispec/image_spec_schema_defs_descriptor.c \
	src/ocispec/image_spec_schema_image_index_schema.c \
	src/ocispec/image_spec_schema_image_layout_schema.c \
	src/ocispec/image_spec_schema_image_manifest_schema.c \
	src/ocispec/image_spec_schema_config_schema.h \
	src/ocispec/image_spec_schema_content_descriptor.h \
	src/ocispec/image_spec_schema_defs.h \
	src/ocispec/image_spec_schema_defs_descriptor.h \
	src/ocispec/image_spec_schema_image_index_schema.h \
	src/ocispec/image_spec_schema_image_layout_schema.h \
	src/ocispec/image_spec_schema_image_manifest_schema.h: src/image_spec_stamp

src/ocispec/runtime_spec_schema_config_linux.h \
	src/ocispec/runtime_spec_schema_config_schema.h \
	src/ocispec/runtime_spec_schema_config_solaris.h \
	src/ocispec/runtime_spec_schema_config_vm.h \
	src/ocispec/runtime_spec_schema_config_windows.h \
	src/ocispec/runtime_spec_schema_defs.h \
	src/ocispec/runtime_spec_schema_defs_linux.h \
	src/ocispec/runtime_spec_schema_defs_zos.h \
	src/ocispec/runtime_spec_schema_features_linux.h \
	src/ocispec/runtime_spec_schema_features_schema.h \
	src/ocispec/runtime_spec_schema_features_linux.c \
	src/ocispec/runtime_spec_schema_features_schema.c \
	src/ocispec/runtime_spec_schema_defs_vm.h \
	src/ocispec/runtime_spec_schema_defs_windows.h \
	src/ocispec/runtime_spec_schema_state_schema.h \
	src/ocispec/runtime_spec_schema_config_linux.c \
	src/ocispec/runtime_spec_schema_config_zos.c \
	src/ocispec/runtime_spec_schema_config_schema.c \
	src/ocispec/runtime_spec_schema_config_solaris.c \
	src/ocispec/runtime_spec_schema_config_vm.c \
	src/ocispec/runtime_spec_schema_config_windows.c \
	src/ocispec/runtime_spec_schema_defs.c \
	src/ocispec/runtime_spec_schema_defs_linux.c \
	src/ocispec/runtime_spec_schema_defs_vm.c \
	src/ocispec/runtime_spec_schema_defs_zos.c \
	src/ocispec/runtime_spec_schema_defs_windows.c \
        src/ocispec/runtime_spec_schema_config_freebsd.h \
        src/ocispec/runtime_spec_schema_defs_freebsd.h \
        src/ocispec/runtime_spec_schema_config_freebsd.c \
        src/ocispec/runtime_spec_schema_defs_freebsd.c \
	src/ocispec/runtime_spec_schema_state_schema.c: src/runtime_spec_stamp

src/ocispec/image_manifest_items_image_manifest_items_schema.h \
	src/ocispec/image_manifest_items_image_manifest_items_schema.c: src/image_manifest_stamp

src/ocispec/basic_test_double_array_item.h \
	src/ocispec/basic_test_double_array.h \
	src/ocispec/basic_test_top_array_int.h \
	src/ocispec/basic_test_top_array_string.h \
	src/ocispec/basic_test_top_double_array_int.h \
	src/ocispec/basic_test_top_double_array_obj.h \
	src/ocispec/basic_test_top_double_array_refobj.h \
	src/ocispec/basic_test_top_double_array_string.h \
	src/ocispec/basic_test_double_array_item.c \
	src/ocispec/basic_test_double_array.c \
	src/ocispec/basic_test_top_array_int.c \
	src/ocispec/basic_test_top_array_string.c \
	src/ocispec/basic_test_top_double_array_int.c \
	src/ocispec/basic_test_top_double_array_obj.c \
	src/ocispec/basic_test_top_double_array_refobj.c \
	src/ocispec/basic_test_top_double_array_string.c: src/basic-test_stamp

$(HEADER_FILES): %.h: %.c src/ocispec/generate.py

BUILT_SOURCES = $(HEADER_FILES) $(SOURCE_FILES)

libocispec_la_SOURCES = $(BUILT_SOURCES) \
	src/ocispec/read-file.c \
	src/ocispec/json_common.c

TMP_H_FILES = $(HEADER_FILES:.h=.h.tmp)
TMP_C_FILES = $(SOURCE_FILES:.c=.c.tmp)

CLEANFILES += $(HEADER_FILES) $(SOURCE_FILES) $(TMP_H_FILES) $(TMP_C_FILES)

TESTS_LDADD = libocispec.la $(SELINUX_LIBS)

if HAVE_EMBEDDED_YAJL
TESTS_LDADD += yajl/libyajl.la
else
TESTS_LDADD += $(YAJL_LIBS)
endif

libocispec_a_SOURCES =

libocispec.a: libocispec.la $(BUILT_SOURCES) src/runtime_spec_stamp src/image_spec_stamp src/image_manifest_stamp src/basic-test_stamp
	$(LIBTOOL) --mode=link $(GCC) libocispec.la -o libocispec.a

if ENABLE_LIBOCISPEC_INSTALL
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ocispec.pc
endif

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

tests_test_11_SOURCES = tests/test-11.c
tests_test_11_LDADD = $(TESTS_LDADD)

tests_test_12_SOURCES = tests/test-12.c
tests_test_12_LDADD = $(TESTS_LDADD)

tests_test_13_SOURCES = tests/test-13.c
tests_test_13_LDADD = $(TESTS_LDADD)

src_ocispec_validate_SOURCES = src/ocispec/validate.c
src_ocispec_validate_LDADD = $(TESTS_LDADD)

TESTS = tests/test-1 \
	tests/test-2 \
	tests/test-3 \
	tests/test-4 \
	tests/test-5 \
	tests/test-6 \
	tests/test-7 \
	tests/test-8 \
	tests/test-9 \
	tests/test-10 \
	tests/test-11 \
	tests/test-12 \
	tests/test-13

noinst_PROGRAMS = src/ocispec/validate $(TESTS)

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
	tests/data/null_value_config.json \
	tests/data/doublearray.json \
	tests/data/top_array_int.json \
	tests/data/top_array_string.json \
	tests/data/top_double_array_int.json \
	tests/data/top_double_array_obj.json \
	tests/data/top_double_array_refobj.json \
	tests/data/top_double_array_string.json \
	tests/data/config-netdevices.json \
	tests/test-spec \
	src/ocispec/generate.py \
	src/ocispec/headers.py \
	src/ocispec/helpers.py \
	src/ocispec/sources.py \
	$(HEADER_FILES) \
	src/ocispec/read-file.h \
	runtime-spec \
	image-spec \
	src/ocispec/json_common.h \
	src/ocispec/json_common.c \
	src/yajl

sync:
	(cd image-spec; git pull https://github.com/opencontainers/image-spec)
	(cd runtime-spec; git pull https://github.com/opencontainers/runtime-spec)
	(cd yajl; git pull https://github.com/containers/yajl main)

generate: src/runtime_spec_stamp src/image_spec_stamp src/image_manifest_stamp src/basic-test_stamp

#Needed by phony: generate-rust
install-node-deps:
	(npm install @apidevtools/json-schema-ref-parser)
	(npm install  quicktype-core)

generate-rust:
	(node rust-gen.js)
