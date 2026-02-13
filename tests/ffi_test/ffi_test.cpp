#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cose_openssl_ffi.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string keys_dir;

static std::vector<uint8_t> read_file(const char *name) {
  std::string path = keys_dir + "/" + name;
  FILE *f = fopen(path.c_str(), "rb");
  assert(f && "failed to open key file");
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> buf(sz);
  size_t n = fread(buf.data(), 1, sz, f);
  assert(n == static_cast<size_t>(sz));
  fclose(f);
  return buf;
}

// Key buffers populated in main().
static std::vector<uint8_t> EC_PRIV_DER, EC_PUB_DER;
#ifdef ENABLE_PQC
static std::vector<uint8_t> MLDSA_PRIV_DER, MLDSA_PUB_DER;
#endif

// Minimal CBOR-encoded empty map: 0xa0
static const uint8_t EMPTY_MAP[] = {0xa0};

// Protected header from the Rust test suite (hex-decoded).
static const uint8_t TEST_PHDR[] = {
    0xa3, 0x19, 0x01, 0x8b, 0x02, 0x0f, 0xa3, 0x06, 0x1a, 0x69, 0x8b, 0x72,
    0x82, 0x01, 0x73, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x65,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x70,
    0x6c, 0x65, 0x64, 0x67, 0x65, 0x72, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61,
    0x74, 0x75, 0x72, 0x65, 0x66, 0x63, 0x63, 0x66, 0x2e, 0x76, 0x31, 0xa1,
    0x64, 0x74, 0x78, 0x69, 0x64, 0x65, 0x32, 0x2e, 0x31, 0x33, 0x34,
};

// ---------------------------------------------------------------------------
// EC Tests
// ---------------------------------------------------------------------------

static void test_sign_verify() {
  printf("  sign + verify ... ");

  const char *payload = "hello from C++";

  uint8_t *out = nullptr;
  size_t out_len = 0;

  int32_t rc =
      cose_sign(TEST_PHDR, sizeof(TEST_PHDR), EMPTY_MAP, sizeof(EMPTY_MAP),
                reinterpret_cast<const uint8_t *>(payload), strlen(payload),
                EC_PRIV_DER.data(), EC_PRIV_DER.size(), &out, &out_len);
  assert(rc == 0);
  assert(out != nullptr);
  assert(out_len > 0);

  rc = cose_verify(out, out_len, EC_PUB_DER.data(), EC_PUB_DER.size());
  assert(rc == 1);

  cose_free(out, out_len);
  printf("  OK\n");
}

static void test_sign_detached_verify_detached() {
  printf("  sign_detached + verify_detached ... ");

  const char *payload = "detached payload";

  uint8_t *out = nullptr;
  size_t out_len = 0;

  int32_t rc = cose_sign_detached(
      TEST_PHDR, sizeof(TEST_PHDR), EMPTY_MAP, sizeof(EMPTY_MAP),
      reinterpret_cast<const uint8_t *>(payload), strlen(payload),
      EC_PRIV_DER.data(), EC_PRIV_DER.size(), &out, &out_len);
  assert(rc == 0);

  // Verify with detached payload succeeds.
  rc = cose_verify_detached(
      out, out_len, reinterpret_cast<const uint8_t *>(payload), strlen(payload),
      EC_PUB_DER.data(), EC_PUB_DER.size());
  assert(rc == 1);

  // Non-detached verify should fail (payload slot is CBOR null).
  rc = cose_verify(out, out_len, EC_PUB_DER.data(), EC_PUB_DER.size());
  assert(rc == -1);

  cose_free(out, out_len);
  printf("OK\n");
}

static void test_verify_wrong_key() {
  printf("  verify with wrong key returns 0 ... ");

  const char *payload = "wrong key test";

  uint8_t *out = nullptr;
  size_t out_len = 0;

  int32_t rc =
      cose_sign(TEST_PHDR, sizeof(TEST_PHDR), EMPTY_MAP, sizeof(EMPTY_MAP),
                reinterpret_cast<const uint8_t *>(payload), strlen(payload),
                EC_PRIV_DER.data(), EC_PRIV_DER.size(), &out, &out_len);
  assert(rc == 0);

  uint8_t garbage[] = {0xde, 0xad, 0xbe, 0xef};
  rc = cose_verify(out, out_len, garbage, sizeof(garbage));
  assert(rc == -1);

  cose_free(out, out_len);
  printf("OK\n");
}

static void test_sign_bad_key() {
  printf("  sign with garbage key returns -1 ... ");

  const char *payload = "bad key";
  uint8_t garbage[] = {0xde, 0xad, 0xbe, 0xef};

  uint8_t *out = nullptr;
  size_t out_len = 0;

  int32_t rc =
      cose_sign(TEST_PHDR, sizeof(TEST_PHDR), EMPTY_MAP, sizeof(EMPTY_MAP),
                reinterpret_cast<const uint8_t *>(payload), strlen(payload),
                garbage, sizeof(garbage), &out, &out_len);
  assert(rc == -1);

  printf("OK\n");
}

// ---------------------------------------------------------------------------
// ML-DSA tests
// ---------------------------------------------------------------------------

#ifdef ENABLE_PQC
static void test_mldsa_sign_verify() {
  printf("  ML-DSA sign + verify ... ");

  const char *payload = "hello from ML-DSA";

  uint8_t *out = nullptr;
  size_t out_len = 0;

  int32_t rc =
      cose_sign(TEST_PHDR, sizeof(TEST_PHDR), EMPTY_MAP, sizeof(EMPTY_MAP),
                reinterpret_cast<const uint8_t *>(payload), strlen(payload),
                MLDSA_PRIV_DER.data(), MLDSA_PRIV_DER.size(), &out, &out_len);
  assert(rc == 0);
  assert(out != nullptr);
  assert(out_len > 0);

  rc = cose_verify(out, out_len, MLDSA_PUB_DER.data(), MLDSA_PUB_DER.size());
  assert(rc == 1);

  cose_free(out, out_len);
  printf("  OK\n");
}

static void test_mldsa_sign_detached_verify_detached() {
  printf("  ML-DSA sign_detached + verify_detached ... ");

  const char *payload = "ML-DSA detached";

  uint8_t *out = nullptr;
  size_t out_len = 0;

  int32_t rc = cose_sign_detached(
      TEST_PHDR, sizeof(TEST_PHDR), EMPTY_MAP, sizeof(EMPTY_MAP),
      reinterpret_cast<const uint8_t *>(payload), strlen(payload),
      MLDSA_PRIV_DER.data(), MLDSA_PRIV_DER.size(), &out, &out_len);
  assert(rc == 0);

  // Verify with detached payload succeeds.
  rc = cose_verify_detached(
      out, out_len, reinterpret_cast<const uint8_t *>(payload), strlen(payload),
      MLDSA_PUB_DER.data(), MLDSA_PUB_DER.size());
  assert(rc == 1);

  // Non-detached verify should fail.
  rc = cose_verify(out, out_len, MLDSA_PUB_DER.data(), MLDSA_PUB_DER.size());
  assert(rc == -1);

  cose_free(out, out_len);
  printf("OK\n");
}
#endif

// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
  keys_dir = (argc > 1) ? argv[1] : "tests/ffi_test/keys";

  EC_PRIV_DER = read_file("ec_priv_der.der");
  EC_PUB_DER = read_file("ec_pub_der.der");
#ifdef ENABLE_PQC
  MLDSA_PRIV_DER = read_file("mldsa_priv_der.der");
  MLDSA_PUB_DER = read_file("mldsa_pub_der.der");
#endif

  printf("cose-openssl-ffi C++ FFI tests (EC P-256):\n");
  test_sign_verify();
  test_sign_detached_verify_detached();
  test_verify_wrong_key();
  test_sign_bad_key();
#ifdef ENABLE_PQC
  printf("\ncose-openssl-ffi C++ FFI tests (ML-DSA-65):\n");
  test_mldsa_sign_verify();
  test_mldsa_sign_detached_verify_detached();
#endif
  printf("\nAll tests passed.\n");
  return 0;
}
