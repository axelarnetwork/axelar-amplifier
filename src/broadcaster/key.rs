use cosmrs::bip32::secp256k1::elliptic_curve::rand_core::OsRng;

/// In contrast to cosmrs::crypto::secp256k1::SigningKey, this key type is sendable so it can be used in contexts when it needs to be moved across thread boundaries
pub struct ECDSASigningKey {
    inner: k256::ecdsa::SigningKey,
}

impl ECDSASigningKey {
    pub fn public_key(&self) -> cosmrs::crypto::PublicKey {
        self.inner.verifying_key().into()
    }

    pub fn random() -> Self {
        Self {
            inner: ecdsa::SigningKey::random(&mut OsRng),
        }
    }
}

impl From<&ECDSASigningKey> for cosmrs::crypto::secp256k1::SigningKey {
    fn from(key: &ECDSASigningKey) -> cosmrs::crypto::secp256k1::SigningKey {
        let signing_key = key.inner.clone();
        cosmrs::crypto::secp256k1::SigningKey::new(Box::new(signing_key))
    }
}
