use snow::{Builder, params::NoiseParams};

use crate::IdentityError;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerPublicKey(Vec<u8>);

impl PeerPublicKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct PeerPrivateKey(Vec<u8>);

impl PeerPrivateKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct PeerKeypair {
    private: PeerPrivateKey,
    public: PeerPublicKey,
}

impl PeerKeypair {
    pub fn public_key(&self) -> &PeerPublicKey {
        &self.public
    }

    pub(crate) fn private_key(&self) -> &PeerPrivateKey {
        &self.private
    }
}

pub fn generate_keypair() -> Result<PeerKeypair, IdentityError> {
    let params = NOISE_PATTERN
        .parse::<NoiseParams>()
        .map_err(|error| IdentityError::Noise(error.to_string()))?;

    let builder = Builder::new(params);

    let keypair = builder
        .generate_keypair()
        .map_err(|error| IdentityError::Noise(error.to_string()))?;

    Ok(PeerKeypair {
        private: PeerPrivateKey(keypair.private),

        public: PeerPublicKey(keypair.public),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypairs_are_different() {
        let first = generate_keypair().expect("first keypair should be generated");

        let second = generate_keypair().expect("second keypair should be generated");

        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn public_key_is_not_empty() {
        let keypair = generate_keypair().expect("keypair should be generated");

        assert!(!keypair.public_key().as_bytes().is_empty());
    }
}
