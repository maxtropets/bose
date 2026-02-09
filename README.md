# bose

Better COSE.

Used purely in research purposes, not intended for production use (yet).

## How-to

Targeting Azure Linux 4.0 with OpenSLL 3.5, to enable PQC.

Currently developed on AL 3.0, CI on cheap Ubuntu.

### How to use with custom OpenSSL version

* Build/install your own OpenSSL at /path/to/openssl.
* export OPENSSL_DIR="/path/to/openss"
* `cargo build` will pick it up for building
* To use, start with `LD_PRELOAD=/path/to/openssl/lib(64)/libcrypto.so:/path/to/openssl/lib(64)/libssl.so`
  * E.g. `LD_PRELOAD=... cargo test`
