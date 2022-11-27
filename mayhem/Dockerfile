FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y gcc cmake make libfuse-dev libmbedtls-dev ruby-dev pkg-config

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libmbedtls-dev ruby-dev
COPY --from=builder /install /install
ENV LD_LIBRARY_PATH=/install/lib
