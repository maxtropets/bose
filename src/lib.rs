mod ossl_wrappers;
mod sign;
mod verify;

pub use sign::sign;
pub use verify::verify;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify() {
        let msg = "Good boy, good boy, good boy...".as_bytes().to_vec();
        let key = ossl_wrappers::SigningKey::new("ML-DSA-44").unwrap();

        let sig = sign(&key, &msg).unwrap();
        println!("key ptr: {:?}, signature length: {:?}", key, sig.len());

        let res = verify(&key, &sig, &msg).unwrap();
        println!("Verifying message result: {}", res);
    }
}
