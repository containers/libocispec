AC_PREREQ([2.63])
AC_INIT([libocispec], [0.3], [giuseppe@scrivano.org])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

LT_INIT([disable-shared])

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_ARG_ENABLE(embedded-yyjson,
AS_HELP_STRING([--enable-embedded-yyjson], [Statically link the embedded yyjson version]),
[
case "${enableval}" in
  yes) embedded_yyjson=true ;;
  no)  embedded_yyjson=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-embedded-yyjson) ;;
esac],[embedded_yyjson=auto])

if test x"$embedded_yyjson" != xtrue; then
PKG_CHECK_MODULES([YYJSON], [yyjson >= 0.8.0], [embedded_yyjson=false], [
  if test x"$embedded_yyjson" = xauto; then
    AC_MSG_NOTICE([yyjson not found on the system, using the embedded version])
    embedded_yyjson=true
  else
    AC_MSG_ERROR([yyjson >= 0.8.0 not found and embedded yyjson is disabled])
  fi
])
fi
AM_CONDITIONAL([HAVE_EMBEDDED_YYJSON], [test x"$embedded_yyjson" = xtrue])

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
