mod ossl_wrappers;
mod sign;
mod verify;

pub use sign::sign;
pub use verify::verify;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ossl_wrappers::{EvpKey, KeyInitData, WhichEC};

    fn sign_verify_with(key_data: KeyInitData) {
        let msg = "Good boy, good boy, good boy...".as_bytes().to_vec();
        let key = EvpKey::new(key_data).unwrap();

        let sig = sign(&key, &msg).unwrap();
        println!("key ptr: {:?}, signature length: {:?}", key, sig.len());

        let res = verify(&key, &sig, &msg).unwrap();
        println!("Verifying message result: {}", res);
    }

    #[cfg(feature = "pqc")]
    mod pqc_tests {
        use super::*;
        use crate::ossl_wrappers::WhichMLDSA;

        #[test]
        fn ml_dsa_44() { sign_verify_with(KeyInitData::MLDSA(WhichMLDSA::P44)); }
        #[test]
        fn ml_dsa_65() { sign_verify_with(KeyInitData::MLDSA(WhichMLDSA::P65)); }
        #[test]
        fn ml_dsa_87() { sign_verify_with(KeyInitData::MLDSA(WhichMLDSA::P87)); }
    }

    #[test]
    fn ec_p256() { sign_verify_with(KeyInitData::EC(WhichEC::P256)); }
    #[test]
    fn ec_p384() { sign_verify_with(KeyInitData::EC(WhichEC::P384)); }
    #[test]
    fn ec_p521() { sign_verify_with(KeyInitData::EC(WhichEC::P521)); }
}
