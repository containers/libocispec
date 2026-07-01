FROM quay.io/fedora/fedora:latest

RUN dnf install -y python3 automake autoconf libtool make git pkg-config clang \
    glibc-static libunwind-devel binutils-devel xz-devel libatomic json-c-devel \
    libzstd-devel

RUN git clone --depth 1 https://github.com/google/honggfuzz.git && cd honggfuzz && sed -i 's/LDFLAGS\s*+=/LDFLAGS += -lzstd/' Makefile && make -j $(nproc) && make install PREFIX=/usr

COPY run-tests.sh /usr/local/bin

WORKDIR /libocispec

ENTRYPOINT /usr/local/bin/run-tests.sh
