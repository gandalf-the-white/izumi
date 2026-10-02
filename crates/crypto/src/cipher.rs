use crate::error::CryptoError;

// pub trait DataCipher: Send + Sync {
//     fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

//     fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
// }

// fn nonce_from_counter(counter: u64) -> [u8; 12] {
//     let mut nonce = [0_u8; 12];

//     nonce[4..].copy_from_slice(&counter.to_be_bytes());

//     nonce
// }

pub trait DataCipher: Send + Sync {
    fn encrypt(&self, sequence: u64, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn decrypt(&self, sequence: u64, ciphertext: &[u8], aad: &[u8])
    -> Result<Vec<u8>, CryptoError>;
}

pub(crate) fn nonce_from_sequence(sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];

    nonce[4..].copy_from_slice(&sequence.to_be_bytes());

    nonce
}
