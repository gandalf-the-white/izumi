use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::{CryptoError, DataCipher};

pub struct Aes256GcmDataCipher {
    cipher: Aes256Gcm,
    counter: u64,
}

impl Aes256GcmDataCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),

            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], CryptoError> {
        let counter = self.counter;

        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;

        let mut nonce = [0_u8; 12];

        nonce[4..].copy_from_slice(&counter.to_be_bytes());

        Ok(nonce)
    }
}

impl DataCipher for Aes256GcmDataCipher {
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce()?;
        let nonce = Nonce::try_from(&nonce[..]).map_err(|_| CryptoError::EncryptionFailed)?;

        self.cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce()?;
        let nonce = Nonce::try_from(&nonce[..]).map_err(|_| CryptoError::DecryptionFailed)?;

        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
