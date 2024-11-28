FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
        autoconf \
        build-essential \
        git \
        libtool \
        pkg-config \
        python3 \
        libjansson-dev


COPY . libocispec

RUN cd libocispec && \
    ./autogen.sh && \
    ./configure CFLAGS='-Wall -Wextra -Werror' && \
    make -j $(nproc) distcheck AM_DISTCHECK_DVI_TARGET="" TESTS="" && \
    make clean
