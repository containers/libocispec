AC_PREREQ([2.63])
AC_INIT([libocispec], [0.4], [giuseppe@scrivano.org])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-shared])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_SEARCH_LIBS(json_c_version, [json-c], [AC_DEFINE([HAVE_JSONC], 1, [Define if json-c is available])], [AC_MSG_ERROR([*** json-c headers not found])])

# Optionally install the library.
AC_ARG_ENABLE(libocispec-install,
AS_HELP_STRING([--enable-libocispec-install], [Enable libocispec installation]),
[
case "${enableval}" in
  yes) libocispec_install=true ;;
  no)  libocispec_install=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-libocispec-install) ;;
esac],[libocispec_install=false])

AM_CONDITIONAL([ENABLE_LIBOCISPEC_INSTALL], [test x"$libocispec_install" = xtrue])

AC_ARG_VAR(OCI_RUNTIME_EXTENSIONS, [extensions for the OCI runtime parser])
AC_ARG_VAR(OCI_IMAGE_EXTENSIONS, [extensions for the OCI image parser])
AC_ARG_VAR(OCI_IMAGE_INDEX_EXTENSIONS, [extensions for the OCI image index parser])
AC_ARG_VAR(OCI_IMAGE_LAYOUT_EXTENSIONS, [extensions for the OCI image layout parser])
AC_ARG_VAR(OCI_IMAGE_MANIFEST_EXTENSIONS, [extensions for the OCI image manifest parser])
AC_ARG_VAR(OCI_IMAGE_MANIFEST_ITEMS_EXTENSIONS, [extensions for the OCI image manifest items parser])

AC_PROG_SED
AC_PROG_CC
AM_PROG_CC_C_O

AM_PATH_PYTHON([3])

AC_CONFIG_FILES([
Makefile
ocispec.pc
])
AC_OUTPUT
