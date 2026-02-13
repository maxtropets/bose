#!/bin/bash
set -e
cd "$(dirname "$0")/.."

OSSL="${OPENSSL_LIB_DIR:-$PWD/openssl-3.5.5}"
OSSL_INC="${OPENSSL_INCLUDE_DIR:-$PWD/openssl-3.5.5/include}"
CARGO=(cargo build --release -p cose-openssl-ffi)
CXX=(g++ -std=c++17 -Wall -Werror -Icpp)
LD_LP=

if [[ "${1:-}" == "--pqc" ]]; then
  CARGO+=(--features cose-openssl-ffi/pqc)
  CXX+=(-DENABLE_PQC "-I$OSSL_INC" "-L$OSSL")
  export OPENSSL_INCLUDE_DIR="$OSSL_INC" OPENSSL_LIB_DIR="$OSSL"
  LD_LP="$OSSL"
fi

"${CARGO[@]}"
"${CXX[@]}" tests/ffi_test/ffi_test.cpp \
  target/release/libcose_openssl_ffi.a -lssl -lcrypto -lpthread -ldl -lm \
  -o tests/ffi_test/ffi_test
LD_LIBRARY_PATH="${LD_LP:+$LD_LP:}${LD_LIBRARY_PATH:-}" tests/ffi_test/ffi_test
