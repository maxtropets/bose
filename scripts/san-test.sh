#!/usr/bin/env bash
set -euo pipefail

# Install nightly if needed
if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    rustup toolchain install nightly || exit 1
fi

# AddressSanitizer
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu || exit 1

# LeakSanitizer
RUSTFLAGS="-Z sanitizer=leak" cargo +nightly test --target x86_64-unknown-linux-gnu || exit 1

# PQC tests if requested
if [ "${1:-}" = "pqc" ]; then
    LD_PRELOAD="openssl-3.5.5/libcrypto.so.3 openssl-3.5.5/libssl.so.3" \
        RUSTFLAGS="-Z sanitizer=address" \
        cargo +nightly test --target x86_64-unknown-linux-gnu --features pqc || exit 1
    
    LD_PRELOAD="openssl-3.5.5/libcrypto.so.3 openssl-3.5.5/libssl.so.3" \
        RUSTFLAGS="-Z sanitizer=leak" \
        cargo +nightly test --target x86_64-unknown-linux-gnu --features pqc || exit 1
fi

# Verify sanitizer detects intentional leak
set +e
LEAK_OUTPUT=$(RUSTFLAGS="-Z sanitizer=leak" \
    cargo +nightly test --target x86_64-unknown-linux-gnu \
    intentional_leak_for_sanitizer_validation -- --ignored 2>&1)
set -e
echo "$LEAK_OUTPUT" | grep -q "LeakSanitizer: detected memory leaks" || exit 1
