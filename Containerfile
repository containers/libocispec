FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
        autoconf \
        build-essential \
        git \
        libtool \
        pkg-config \
        python3


COPY . libocispec

RUN git clone https://github.com/akheron/jansson

RUN cd jansson && autoreconf -fi && ./configure && make && make install

RUN cd libocispec && \
    export JANSSON_CFLAGS=-I/usr/local/include && \
    export JANSSON_LIBS=/usr/local/lib/libjansson.so && \
    ./autogen.sh && \
    ./configure CFLAGS='-Wall -Wextra -Werror' && \
    make -j $(nproc) distcheck DISTCHECK_CONFIGURE_FLAGS="--enable-embedded-yajl" AM_DISTCHECK_DVI_TARGET="" TESTS="" && \
    make clean