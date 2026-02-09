#!/bin/bash
set -ex

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --component rustfmt
export PATH="$HOME/.cargo/bin:$PATH"
