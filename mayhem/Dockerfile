FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y gcc cmake make libfuse-dev libmbedtls-dev ruby-dev pkg-config clang

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install
RUN sed -i 's/dis_crypt_t dis_crypt_new/extern "C" dis_crypt_t dis_crypt_new/' /repo/include/dislocker/encryption/encommon.h
RUN clang++ /repo/mayhem/fuzz_dis_crypt_new.cpp -fsanitize=fuzzer,address -L /install/lib/ -ldislocker -o /fuzz -I /repo/include/dislocker/encryption/

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libmbedtls-dev ruby-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_dis_crypt_new
ENV LD_LIBRARY_PATH=/install/lib
