#!/bin/sh

(cd yajl; ./autogen.sh)

git submodule update --init --recursive

test -n "$srcdir" || srcdir=`dirname "$0"`
test -n "$srcdir" || srcdir=.

olddir=`pwd`
cd $srcdir

if ! (autoreconf --version >/dev/null 2>&1); then
        echo "*** No autoreconf found, please install it ***"
        exit 1
fi

(cd ./jansson; autoreconf -i)

mkdir -p m4

autoreconf --force --install --verbose

cd $olddir
test -n "$NOCONFIGURE" || "$srcdir/configure" "$@"
