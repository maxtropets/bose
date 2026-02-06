use crate::ossl_wrappers::{SigningContext, SigningKey};

use openssl_sys as ossl;
use std::ptr;

pub fn sign(key: &SigningKey, msg: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let ctx = SigningContext::new(&key)?;
        let res =
            ossl::EVP_PKEY_sign_message_init(ctx.ctx, key.sig, ptr::null_mut());
        if res != 1 {
            return Err(format!(
                "Failed to sign: init message ctx, err: {}",
                res
            ));
        }

        let mut sig_size: usize = 0;
        let res = ossl::EVP_PKEY_sign(
            ctx.ctx,
            ptr::null_mut(),
            &mut sig_size,
            msg.as_ptr(),
            msg.len(),
        );
        if res != 1 {
            return Err(format!("Failed to sign: get sig size, err: {}", res));
        }

        let mut sig = vec![0u8; sig_size];
        let res = ossl::EVP_PKEY_sign(
            ctx.ctx,
            sig.as_mut_ptr(),
            &mut sig_size,
            msg.as_ptr(),
            msg.len(),
        );
        if res != 1 {
            return Err(format!("Failed to sign: sign, err: {}", res));
        }

        Ok(sig)
    }
}
