AC_PREREQ([2.63])
AC_INIT([libocispec], [0.2], [giuseppe@scrivano.org])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-shared])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AM_EXTRA_RECURSIVE_TARGETS([yajl])
AC_CONFIG_SUBDIRS([yajl])

AC_ARG_ENABLE(embedded-yajl,
AS_HELP_STRING([--enable-embedded-yajl], [Statically link a modified yajl version]),
[
case "${enableval}" in
  yes) embedded_yajl=true ;;
  no)  embedded_yajl=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-embedded-yajl) ;;
esac],[embedded_yajl=false])

AM_CONDITIONAL([HAVE_EMBEDDED_YAJL], [test x"$embedded_yajl" == xtrue])
AM_COND_IF([HAVE_EMBEDDED_YAJL], [], [PKG_CHECK_MODULES([YAJL], [yajl >= 2.1.0])])

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
])
AC_OUTPUT
