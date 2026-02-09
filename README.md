# bose

Better COSE.

Used purely in research purposes, not intended for production use (yet).

## How-to

Targeting Azure Linux 4.0 with OpenSSL 3.5, to enable PQC.

Currently developed on AL 3.0, CI on a cheap Ubuntu image, with optional OpenSSL 3.5 build if needed (label-triggered).

### How to test for PQC

* Check `scripts/setup-openssl.sh` for how to build OpenSSL from source.
* Set env (or prepend before `cargo`):
  ```bash
  export OPENSSL_INCLUDE_DIR="/path/to/openssl/include"
  export OPENSSL_LIB_DIR="/path/to/openssl"
  export LD_PRELOAD="/path/to/openssl/libcrypto.so:/path/to/openssl/libssl.so"
  ```
* `cargo test --features pqc`
