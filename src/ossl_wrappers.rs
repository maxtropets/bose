use openssl_sys as ossl;
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr;

#[cfg(feature = "pqc")]
unsafe extern "C" {
    fn EVP_PKEY_is_a(
        pkey: *const ossl::EVP_PKEY,
        name: *const std::ffi::c_char,
    ) -> std::ffi::c_int;
}

#[cfg(feature = "pqc")]
#[derive(Debug)]
pub enum WhichMLDSA {
    P44,
    P65,
    P87,
}

#[cfg(feature = "pqc")]
impl WhichMLDSA {
    fn openssl_str(&self) -> &'static str {
        match self {
            WhichMLDSA::P44 => "ML-DSA-44",
            WhichMLDSA::P65 => "ML-DSA-65",
            WhichMLDSA::P87 => "ML-DSA-87",
        }
    }
}

#[derive(Debug)]
pub enum WhichEC {
    P256,
    P384,
    P521,
}

impl WhichEC {
    fn openssl_str(&self) -> &'static str {
        match self {
            WhichEC::P256 => "P-256",
            WhichEC::P384 => "P-384",
            WhichEC::P521 => "P-521",
        }
    }
}

#[derive(Debug)]
pub enum KeyType {
    #[cfg(feature = "pqc")]
    MLDSA(WhichMLDSA),
    EC(WhichEC),
}

#[derive(Debug)]
pub struct EvpKey {
    pub key: *mut ossl::EVP_PKEY,
    pub typ: KeyType,
}

impl EvpKey {
    pub fn new(typ: KeyType) -> Result<Self, String> {
        unsafe {
            let key = match &typ {
                #[cfg(feature = "pqc")]
                KeyType::MLDSA(which) => {
                    let alg = CString::new(which.openssl_str()).unwrap();
                    ossl::EVP_PKEY_Q_keygen(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        alg.as_ptr(),
                    )
                }
                KeyType::EC(which) => {
                    let crv = CString::new(which.openssl_str()).unwrap();
                    let alg = CString::new("EC").unwrap();
                    ossl::EVP_PKEY_Q_keygen(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        alg.as_ptr(),
                        crv.as_ptr(),
                    )
                }
            };

            if key.is_null() {
                return Err("Failed to create signing key".to_string());
            }

            Ok(EvpKey { key, typ })
        }
    }

    /// Create an `EvpKey` from a DER-encoded SubjectPublicKeyInfo.
    /// Automatically detects key type (EC curve or ML-DSA variant).
    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        // Parse DER using raw OpenSSL API
        let raw = unsafe {
            let mut ptr = der.as_ptr();
            let key =
                ossl::d2i_PUBKEY(ptr::null_mut(), &mut ptr, der.len() as i64);
            if key.is_null() {
                return Err("Failed to parse DER public key".to_string());
            }
            key
        };

        // Detect key type using raw OpenSSL APIs
        let typ = match Self::detect_key_type_raw(raw) {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    ossl::EVP_PKEY_free(raw);
                }
                return Err(e);
            }
        };

        Ok(EvpKey { key: raw, typ })
    }

    /// Create an `EvpKey` from a DER-encoded private key
    /// (PKCS#8 or traditional format).
    /// Automatically detects key type (EC curve or ML-DSA variant).
    pub fn from_der_private(der: &[u8]) -> Result<Self, String> {
        let raw = unsafe {
            let mut ptr = der.as_ptr();
            let key = ossl::d2i_AutoPrivateKey(
                ptr::null_mut(),
                &mut ptr,
                der.len() as i64,
            );
            if key.is_null() {
                return Err("Failed to parse DER private key".to_string());
            }
            key
        };

        let typ = match Self::detect_key_type_raw(raw) {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    ossl::EVP_PKEY_free(raw);
                }
                return Err(e);
            }
        };

        Ok(EvpKey { key: raw, typ })
    }

    fn detect_key_type_raw(
        pkey: *mut ossl::EVP_PKEY,
    ) -> Result<KeyType, String> {
        unsafe {
            let key_id = ossl::EVP_PKEY_id(pkey);

            // EC key type (NID_X9_62_id_ecPublicKey = 408)
            if key_id == 408 {
                let ec_key = ossl::EVP_PKEY_get1_EC_KEY(pkey);
                if ec_key.is_null() {
                    return Err("Failed to get EC key".to_string());
                }

                let group = ossl::EC_KEY_get0_group(ec_key);
                if group.is_null() {
                    ossl::EC_KEY_free(ec_key);
                    return Err("Failed to get EC group".to_string());
                }

                let nid = ossl::EC_GROUP_get_curve_name(group);
                ossl::EC_KEY_free(ec_key);

                let which = match nid {
                    415 => WhichEC::P256, // NID_X9_62_prime256v1
                    715 => WhichEC::P384, // NID_secp384r1
                    716 => WhichEC::P521, // NID_secp521r1
                    _ => {
                        return Err(format!(
                            "Unsupported EC curve NID: {}",
                            nid
                        ));
                    }
                };
                return Ok(KeyType::EC(which));
            }

            #[cfg(feature = "pqc")]
            {
                let mldsa_variants = [
                    ("ML-DSA-44", WhichMLDSA::P44),
                    ("ML-DSA-65", WhichMLDSA::P65),
                    ("ML-DSA-87", WhichMLDSA::P87),
                ];
                for (name, variant) in mldsa_variants {
                    let cname = CString::new(name).unwrap();
                    let is_a = EVP_PKEY_is_a(pkey as *const _, cname.as_ptr());
                    if is_a == 1 {
                        return Ok(KeyType::MLDSA(variant));
                    }
                }
            }

            Err(format!("Unsupported key type (id={})", key_id))
        }
    }

    /// Export the public key as DER-encoded SubjectPublicKeyInfo.
    pub fn to_der(&self) -> Result<Vec<u8>, String> {
        unsafe {
            // Use raw OpenSSL API to avoid needing from_ptr()
            let mut der_ptr: *mut u8 = ptr::null_mut();
            let len = ossl::i2d_PUBKEY(self.key, &mut der_ptr);

            if len <= 0 || der_ptr.is_null() {
                return Err(format!(
                    "Failed to encode public key to DER (rc={})",
                    len
                ));
            }

            // Copy the DER data into a Vec and free the OpenSSL-allocated memory
            let der_slice = std::slice::from_raw_parts(der_ptr, len as usize);
            let der = der_slice.to_vec();
            ossl::CRYPTO_free(
                der_ptr as *mut std::ffi::c_void,
                concat!(file!(), "\0").as_ptr() as *const i8,
                line!() as i32,
            );

            Ok(der)
        }
    }

    /// Export the private key as DER-encoded traditional format.
    pub fn to_der_private(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let mut der_ptr: *mut u8 = ptr::null_mut();
            let len = ossl::i2d_PrivateKey(self.key, &mut der_ptr);

            if len <= 0 || der_ptr.is_null() {
                return Err(format!(
                    "Failed to encode private key to DER (rc={})",
                    len
                ));
            }

            let der_slice = std::slice::from_raw_parts(der_ptr, len as usize);
            let der = der_slice.to_vec();
            ossl::CRYPTO_free(
                der_ptr as *mut std::ffi::c_void,
                concat!(file!(), "\0").as_ptr() as *const i8,
                line!() as i32,
            );

            Ok(der)
        }
    }
}

impl Drop for EvpKey {
    fn drop(&mut self) {
        unsafe {
            if !self.key.is_null() {
                ossl::EVP_PKEY_free(self.key);
            }
        }
    }
}

#[derive(Debug)]
pub struct EvpMdContext<T> {
    op: PhantomData<T>,
    pub ctx: *mut ossl::EVP_MD_CTX,
}

pub struct SignOp;
pub struct VerifyOp;

pub trait ContextInit {
    fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        key: *mut ossl::EVP_PKEY,
    ) -> Result<(), i32>;
    fn purpose() -> &'static str;
}

impl ContextInit for SignOp {
    fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        key: *mut ossl::EVP_PKEY,
    ) -> Result<(), i32> {
        unsafe {
            let rc = ossl::EVP_DigestSignInit(
                ctx,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                key,
            );
            match rc {
                1 => Ok(()),
                err => Err(err),
            }
        }
    }
    fn purpose() -> &'static str {
        "Sign"
    }
}

impl ContextInit for VerifyOp {
    fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        key: *mut ossl::EVP_PKEY,
    ) -> Result<(), i32> {
        unsafe {
            let rc = ossl::EVP_DigestVerifyInit(
                ctx,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                key,
            );
            match rc {
                1 => Ok(()),
                err => Err(err),
            }
        }
    }
    fn purpose() -> &'static str {
        "Verify"
    }
}

impl<T: ContextInit> EvpMdContext<T> {
    pub fn new(key: &EvpKey) -> Result<Self, String> {
        unsafe {
            let ctx = ossl::EVP_MD_CTX_new();
            if ctx.is_null() {
                return Err(format!(
                    "Failed to create ctx for: {}",
                    T::purpose()
                ));
            }
            if let Err(err) = T::init(ctx, key.key) {
                ossl::EVP_MD_CTX_free(ctx);
                return Err(format!(
                    "Failed to init context for {} with err {}",
                    T::purpose(),
                    err
                ));
            }
            Ok(EvpMdContext {
                op: PhantomData,
                ctx,
            })
        }
    }
}

impl<T> Drop for EvpMdContext<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                ossl::EVP_MD_CTX_free(self.ctx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg(feature = "pqc")]
    fn create_ml_dsa_keys() {
        assert!(EvpKey::new(KeyType::MLDSA(WhichMLDSA::P44)).is_ok());
        assert!(EvpKey::new(KeyType::MLDSA(WhichMLDSA::P65)).is_ok());
        assert!(EvpKey::new(KeyType::MLDSA(WhichMLDSA::P87)).is_ok());
    }

    #[test]
    fn create_ec_keys() {
        assert!(EvpKey::new(KeyType::EC(WhichEC::P256)).is_ok());
        assert!(EvpKey::new(KeyType::EC(WhichEC::P384)).is_ok());
        assert!(EvpKey::new(KeyType::EC(WhichEC::P521)).is_ok());
    }

    #[test]
    fn ec_key_from_der_roundtrip() {
        for which in [WhichEC::P256, WhichEC::P384, WhichEC::P521] {
            let key = EvpKey::new(KeyType::EC(which)).unwrap();
            let der = key.to_der().unwrap();
            let imported = EvpKey::from_der(&der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::EC(_)),
                "Expected EC key type"
            );

            // Verify the reimported key exports the same DER
            let der2 = imported.to_der().unwrap();
            assert_eq!(der, der2);
        }
    }

    #[test]
    fn ec_key_from_der_p256() {
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        let der = key.to_der().unwrap();
        let imported = EvpKey::from_der(&der).unwrap();

        assert!(matches!(imported.typ, KeyType::EC(WhichEC::P256)));
    }

    #[test]
    fn from_der_rejects_garbage() {
        assert!(EvpKey::from_der(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    #[test]
    #[cfg(feature = "pqc")]
    fn ml_dsa_key_from_der_roundtrip() {
        for which in [WhichMLDSA::P44, WhichMLDSA::P65, WhichMLDSA::P87] {
            let key = EvpKey::new(KeyType::MLDSA(which)).unwrap();
            let der = key.to_der().unwrap();
            let imported = EvpKey::from_der(&der).unwrap();
            assert!(
                matches!(imported.typ, KeyType::MLDSA(_)),
                "Expected ML-DSA key type"
            );
            let der2 = imported.to_der().unwrap();
            assert_eq!(der, der2);
        }
    }

    #[test]
    #[ignore]
    fn intentional_leak_for_sanitizer_validation() {
        // This test intentionally leaks memory to verify sanitizers
        // detect it if not ignored.
        let key = EvpKey::new(KeyType::EC(WhichEC::P256)).unwrap();
        std::mem::forget(key);
    }
}
