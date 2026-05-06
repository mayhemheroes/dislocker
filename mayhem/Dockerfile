FROM --platform=linux/amd64 ubuntu:20.04 AS builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    gcc cmake make libfuse3-dev ruby-dev pkg-config clang \
    git ca-certificates python3

# Build MbedTLS 3.x from source (Ubuntu 20.04 only ships 2.x, but dislocker requires 3)
# v3.6.x uses a git submodule (framework), so --recurse-submodules is required
RUN git clone --depth=1 --recurse-submodules --branch v3.6.2 \
      https://github.com/Mbed-TLS/mbedtls.git /mbedtls && \
    cmake -S /mbedtls -B /mbedtls/build \
          -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DENABLE_TESTING=OFF \
          -DENABLE_PROGRAMS=OFF \
          -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc) -C /mbedtls/build && \
    make install -C /mbedtls/build

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN sed -i 's/dis_crypt_t dis_crypt_new/extern "C" dis_crypt_t dis_crypt_new/' /repo/include/dislocker/encryption/encommon.h
RUN clang++ /repo/mayhem/fuzz_dis_crypt_new.cpp -fsanitize=fuzzer,address -L /install/lib/ -ldislocker -o /fuzz -I /repo/include/dislocker/encryption/

FROM ubuntu:20.04 AS package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y ruby-dev libfuse3-dev
COPY --from=builder /usr/local/lib/libmbedcrypto* /usr/local/lib/
COPY --from=builder /usr/local/lib/libmbedtls* /usr/local/lib/
COPY --from=builder /usr/local/lib/libmbedx509* /usr/local/lib/
RUN ldconfig
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_dis_crypt_new
ENV LD_LIBRARY_PATH=/install/lib:/usr/local/lib
