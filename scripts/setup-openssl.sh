#!/bin/bash
set -ex

curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.5.5/openssl-3.5.5.tar.gz
tar -xvf openssl-3.5.5.tar.gz 
cd openssl-3.5.5
./Configure --prefix=/opt/openssl
make -j$(nproc)
make install

export OPENSSL_DIR=/opt/openssl
export LD_PRELOAD=/opt/openssl/lib64/libcrypto.so:/opt/openssl/lib64/libssl.so