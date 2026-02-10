use openssl_sys as ossl;
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr;

#[derive(Debug)]
pub struct EvpKey {
    pub key: *mut ossl::EVP_PKEY,
}

#[cfg(feature = "pqc")]
pub enum WhichMLDSA {
    P44,
    P65,
    P87,
}

pub enum WhichEC {
    P256,
    P384,
    P521,
}

pub enum KeyInitData {
    #[cfg(feature = "pqc")]
    MLDSA(WhichMLDSA),
    EC(WhichEC),
}

impl EvpKey {
    pub fn new(data: KeyInitData) -> Result<Self, String> {
        unsafe {
            let key = match data {
                #[cfg(feature = "pqc")]
                KeyInitData::MLDSA(which) => {
                    let alg = CString::new(match which {
                        WhichMLDSA::P44 => "ML-DSA-44",
                        WhichMLDSA::P65 => "ML-DSA-65",
                        WhichMLDSA::P87 => "ML-DSA-87",
                    })
                    .unwrap();
                    ossl::EVP_PKEY_Q_keygen(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        alg.as_ptr(),
                    )
                }
                KeyInitData::EC(which) => {
                    let crv = CString::new(match which {
                        WhichEC::P256 => "P-256",
                        WhichEC::P384 => "P-384",
                        WhichEC::P521 => "P-521",
                    })
                    .unwrap();
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

            Ok(EvpKey { key })
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
    unsafe fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        key: *mut ossl::EVP_PKEY,
    ) -> Result<(), i32>;
    fn purpose() -> &'static str;
}

impl ContextInit for SignOp {
    unsafe fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        key: *mut ossl::EVP_PKEY,
    ) -> Result<(), i32> {
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
    fn purpose() -> &'static str {
        "Sign"
    }
}

impl ContextInit for VerifyOp {
    unsafe fn init(
        ctx: *mut ossl::EVP_MD_CTX,
        key: *mut ossl::EVP_PKEY,
    ) -> Result<(), i32> {
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
        assert!(EvpKey::new(KeyInitData::MLDSA(WhichMLDSA::P44)).is_ok());
        assert!(EvpKey::new(KeyInitData::MLDSA(WhichMLDSA::P65)).is_ok());
        assert!(EvpKey::new(KeyInitData::MLDSA(WhichMLDSA::P87)).is_ok());
    }

    #[test]
    fn create_ec_keys() {
        assert!(EvpKey::new(KeyInitData::EC(WhichEC::P256)).is_ok());
        assert!(EvpKey::new(KeyInitData::EC(WhichEC::P384)).is_ok());
        assert!(EvpKey::new(KeyInitData::EC(WhichEC::P521)).is_ok());
    }
}
