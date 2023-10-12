#[cfg(test)]
mod tests {
    use ecdsa::SigningKey;
    use rand::rngs::OsRng;

    use crate::types::{PublicKey, TMAddress};

    impl TMAddress {
        pub fn random(prefix: &str) -> Self {
            Self(
                PublicKey::from(SigningKey::random(&mut OsRng).verifying_key())
                    .account_id(prefix)
                    .expect("failed to convert to account identifier"),
            )
        }
    }
}
