use crate::ossl_wrappers::{EvpMdContext, EvpKey, MdCtxPurpose};

use openssl_sys as ossl;

pub fn verify(
    key: &EvpKey,
    sig: &[u8],
    msg: &[u8],
) -> Result<bool, String> {
    unsafe {
        let ctx = EvpMdContext::new(&key, MdCtxPurpose::Verify)?;

        let res = ossl::EVP_DigestVerify(
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
