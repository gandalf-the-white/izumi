use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("nonce space exhausted")]
    NonceExhausted,

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("key derivation failed")]
    KeyDerivationFailed,

    #[error("unsupported cryptographic suite")]
    UnsupportedSuite,
}
