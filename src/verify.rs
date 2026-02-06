use crate::ossl_wrappers::{SigningContext, SigningKey};

use openssl_sys as ossl;
use std::ptr;

pub fn verify(
    key: &SigningKey,
    sig: &[u8],
    msg: &[u8],
) -> Result<bool, String> {
    unsafe {
        let ctx = SigningContext::new(&key)?;

        let res = ossl::EVP_PKEY_verify_message_init(
            ctx.ctx,
            key.sig,
            ptr::null_mut(),
        );
        if res != 1 {
            return Err(format!(
                "Failed to verify: init message ctx, err: {}",
                res
            ));
        }

        let res = ossl::EVP_PKEY_verify(
            ctx.ctx,
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
        );
        match res {
            1 => Ok(true),
            0 => Ok(false),
            err => Err(format!("Verify failed with err: {}", err)),
        }
    }
}
