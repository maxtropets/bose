#!/bin/bash
set -ex

curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.5.5/openssl-3.5.5.tar.gz
tar -xvf openssl-3.5.5.tar.gz
cd openssl-3.5.5
./Configure
make -j$(nproc)

# Run as source ./scripts/setup-openssl.sh to have this set.
export OPENSSL_INCLUDE_DIR="$PWD/include"
export OPENSSL_LIB_DIR="$PWD"
export LD_PRELOAD="$PWD/libcrypto.so:$PWD/libssl.so"
