# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

# Uninstall old Rust & Install the latest one.
RUN if which rustup; then rustup self uninstall -y; fi && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /rustup.sh && \
    sh /rustup.sh --default-toolchain nightly-2023-09-21 -y && \
    rm /rustup.sh

# Install dependencies.
RUN apt-get update && \
    apt-get remove -y llvm-10 && \
    apt-get install -y \
        build-essential lsb-release wget software-properties-common gnupg \
        cargo && \
    apt-get install -y wget libstdc++5 libtool-bin automake flex bison \
        libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
        apt-utils apt-transport-https ca-certificates joe curl && \
    yes | bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)" llvm.sh 17 && \
    PATH="/root/.cargo/bin/:$PATH" cargo install cargo-make && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Download libafl.
RUN git clone https://github.com/am009/LibAFL /libafl

# Checkout a current commit
RUN cd /libafl && git pull && git checkout 4f75cb3e59b117fa3e2a95a07ba154f6381ecc46
# Note that due a nightly bug it is currently fixed to a known version on top!


# export LLVM_BINDIR=/usr/local/bin && \
# export LLVM_VERSION=15 && \
# Compile libafl. Let the compiler wrapper call clang 15 in the base image to prevent build failures!!
RUN cd /libafl && \
    unset CFLAGS CXXFLAGS && \
    export LIBAFL_EDGES_MAP_SIZE=2621440 && \
    export LLVM_CONFIG=/usr/local/bin/llvm-config && \
    cd ./fuzzers/fuzzbench && \
    PATH="/root/.cargo/bin/:$PATH" cargo build --profile release-fuzzbench --features no_link_main

# Auxiliary weak references.
RUN cd /libafl/fuzzers/fuzzbench && \
    clang -c stub_rt.c && \
    ar r /stub_rt.a stub_rt.o
