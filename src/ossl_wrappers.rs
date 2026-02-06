use openssl_sys as ossl;
use std::ffi::CString;
use std::ptr;

#[derive(Debug)]
pub struct SigningKey {
    pub key: *mut ossl::EVP_PKEY,
    pub sig: *mut ossl::EVP_SIGNATURE,
}

impl SigningKey {
    pub fn new(alg: &str) -> Result<Self, String> {
        let c_alg = CString::new(alg).unwrap();
        unsafe {
            let key = ossl::EVP_PKEY_Q_keygen(
                ptr::null_mut(),
                ptr::null_mut(),
                c_alg.as_ptr(),
            );
            if key.is_null() {
                return Err("Failed to create signing key".to_string());
            }

            let sig = ossl::EVP_SIGNATURE_fetch(
                ptr::null_mut(),
                c_alg.as_ptr(),
                ptr::null_mut(),
            );
            if sig.is_null() {
                ossl::EVP_PKEY_free(key);
                return Err("Failed to create signing algorithm".to_string());
            }

            Ok(SigningKey { key, sig })
        }
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        unsafe {
            if !self.key.is_null() {
                ossl::EVP_PKEY_free(self.key);
            }
            if !self.sig.is_null() {
                ossl::EVP_SIGNATURE_free(self.sig);
            }
        }
    }
}

#[derive(Debug)]
pub struct SigningContext {
    pub ctx: *mut ossl::EVP_PKEY_CTX,
}

impl SigningContext {
    pub fn new(key: &SigningKey) -> Result<Self, String> {
        unsafe {
            let ctx = ossl::EVP_PKEY_CTX_new(key.key, ptr::null_mut());
            if ctx.is_null() {
                return Err("Failed to sign: create ctx".to_string());
            }
            Ok(SigningContext { ctx })
        }
    }
}

impl Drop for SigningContext {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                ossl::EVP_PKEY_CTX_free(self.ctx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_key() {
        assert!(SigningKey::new("ML-DSA-404").is_err());
    }

    #[test]
    fn good_ml_dsa() {
        assert!(SigningKey::new("ML-DSA-44").is_ok());
        assert!(SigningKey::new("ML-DSA-65").is_ok());
        assert!(SigningKey::new("ML-DSA-87").is_ok());
    }
}
