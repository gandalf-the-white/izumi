use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};

use crate::{CryptoError, DataCipher};

pub struct ChaCha20Poly1305DataCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl ChaCha20Poly1305DataCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),

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

impl DataCipher for ChaCha20Poly1305DataCipher {
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
