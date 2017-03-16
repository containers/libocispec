AC_PREREQ([2.63])
AC_INIT([libocispec], [0.1.1], [giuseppe@scrivano.org])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_CC_C_O

PKG_CHECK_MODULES(JSON_GLIB, [json-glib-1.0])
PKG_CHECK_MODULES(GIO_UNIX, [gio-unix-2.0])
PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])

AC_CHECK_LIB(seccomp, seccomp_rule_add)

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT
