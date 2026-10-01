use crypto::{
    Aes256GcmDataCipher, ChaCha20Poly1305DataCipher, DataCipher, EphemeralKeyExchange,
    derive_directional_keys,
};

// #[test]
// fn chacha_encrypts_and_decrypts() {
//     let key = [42_u8; 32];

//     let mut sender = ChaCha20Poly1305DataCipher::new(&key);

//     let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

//     let plaintext = b"hello secure proxy";

//     let aad = b"session-123";

//     let ciphertext = sender.encrypt(plaintext, aad).expect("encryption");

//     assert_ne!(ciphertext, plaintext);

//     let decrypted = receiver.decrypt(&ciphertext, aad).expect("decryption");

//     assert_eq!(decrypted, plaintext);
// }

// #[test]
// fn aes_encrypts_and_decrypts() {
//     let key = [42_u8; 32];

//     let mut sender = Aes256GcmDataCipher::new(&key);

//     let mut receiver = Aes256GcmDataCipher::new(&key);

//     let plaintext = b"hello secure proxy";

//     let aad = b"session-123";

//     let ciphertext = sender.encrypt(plaintext, aad).expect("encryption");

//     assert_ne!(ciphertext, plaintext);

//     let decrypted = receiver.decrypt(&ciphertext, aad).expect("decryption");

//     assert_eq!(decrypted, plaintext);
// }

// #[test]
// fn modified_ciphertext_is_rejected() {
//     let key = [42_u8; 32];

//     let mut sender = ChaCha20Poly1305DataCipher::new(&key);

//     let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

//     let mut ciphertext = sender.encrypt(b"secret", b"session").unwrap();

//     ciphertext[0] ^= 0x01;

//     let result = receiver.decrypt(&ciphertext, b"session");

//     assert!(matches!(result, Err(crypto::CryptoError::DecryptionFailed)));
// }

// #[test]
// fn wrong_aad_is_rejected() {
//     let key = [42_u8; 32];

//     let mut sender = ChaCha20Poly1305DataCipher::new(&key);

//     let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

//     let ciphertext = sender.encrypt(b"secret", b"session-A").unwrap();

//     let result = receiver.decrypt(&ciphertext, b"session-B");

//     assert!(result.is_err());
// }

// #[test]
// fn x25519_produces_same_shared_secret() {
//     let alice = EphemeralKeyExchange::generate();

//     let bob = EphemeralKeyExchange::generate();

//     let alice_public = alice.public_key();

//     let bob_public = bob.public_key();

//     let alice_secret = alice.shared_secret(bob_public);

//     let bob_secret = bob.shared_secret(alice_public);

//     assert_eq!(alice_secret, bob_secret);
// }

// #[test]
// fn directional_keys_are_different() {
//     let secret = [7_u8; 32];

//     let keys = derive_directional_keys(&secret, "session-123", "chacha20poly1305").unwrap();

//     assert_ne!(keys.initiator_to_responder, keys.responder_to_initiator);
// }

// #[test]
// fn derivation_is_deterministic() {
//     let secret = [7_u8; 32];

//     let first = derive_directional_keys(&secret, "session-123", "chacha20poly1305").unwrap();

//     let second = derive_directional_keys(&secret, "session-123", "chacha20poly1305").unwrap();

//     assert_eq!(first.initiator_to_responder, second.initiator_to_responder);

//     assert_eq!(first.responder_to_initiator, second.responder_to_initiator);
// }

// ============================================================
// ChaCha20-Poly1305
// ============================================================

#[test]
fn chacha_encrypts_and_decrypts() {
    let key = [42_u8; 32];

    let mut sender = ChaCha20Poly1305DataCipher::new(&key);

    let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

    let plaintext = b"hello secure proxy";

    let aad = b"session-123";

    let ciphertext = sender
        .encrypt(plaintext, aad)
        .expect("ChaCha20 encryption should succeed");

    assert_ne!(ciphertext, plaintext);

    let decrypted = receiver
        .decrypt(&ciphertext, aad)
        .expect("ChaCha20 decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha_rejects_modified_ciphertext() {
    let key = [42_u8; 32];

    let mut sender = ChaCha20Poly1305DataCipher::new(&key);

    let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

    let mut ciphertext = sender
        .encrypt(b"very secret message", b"session-123")
        .expect("encryption should succeed");

    ciphertext[0] ^= 0x01;

    let result = receiver.decrypt(&ciphertext, b"session-123");

    assert!(result.is_err(), "modified ciphertext must be rejected");
}

#[test]
fn chacha_rejects_wrong_aad() {
    let key = [42_u8; 32];

    let mut sender = ChaCha20Poly1305DataCipher::new(&key);

    let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

    let ciphertext = sender
        .encrypt(b"secret", b"session-A")
        .expect("encryption should succeed");

    let result = receiver.decrypt(&ciphertext, b"session-B");

    assert!(
        result.is_err(),
        "ciphertext must not authenticate with different AAD"
    );
}

// ============================================================
// AES-256-GCM
// ============================================================

#[test]
fn aes256gcm_encrypts_and_decrypts() {
    let key = [24_u8; 32];

    let mut sender = Aes256GcmDataCipher::new(&key);

    let mut receiver = Aes256GcmDataCipher::new(&key);

    let plaintext = b"hello using AES-256-GCM";

    let aad = b"session-aes";

    let ciphertext = sender
        .encrypt(plaintext, aad)
        .expect("AES encryption should succeed");

    assert_ne!(ciphertext, plaintext);

    let decrypted = receiver
        .decrypt(&ciphertext, aad)
        .expect("AES decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn aes256gcm_rejects_modified_ciphertext() {
    let key = [24_u8; 32];

    let mut sender = Aes256GcmDataCipher::new(&key);

    let mut receiver = Aes256GcmDataCipher::new(&key);

    let mut ciphertext = sender
        .encrypt(b"secret", b"session-aes")
        .expect("encryption should succeed");

    let last = ciphertext.len() - 1;

    ciphertext[last] ^= 0x01;

    let result = receiver.decrypt(&ciphertext, b"session-aes");

    assert!(result.is_err(), "modified ciphertext must be rejected");
}

#[test]
fn aes256gcm_rejects_wrong_aad() {
    let key = [24_u8; 32];

    let mut sender = Aes256GcmDataCipher::new(&key);

    let mut receiver = Aes256GcmDataCipher::new(&key);

    let ciphertext = sender
        .encrypt(b"secret", b"session-A")
        .expect("encryption should succeed");

    let result = receiver.decrypt(&ciphertext, b"session-B");

    assert!(
        result.is_err(),
        "ciphertext must not authenticate with different AAD"
    );
}

// ============================================================
// Nonce / sequence behaviour
// ============================================================

#[test]
fn successive_messages_use_different_ciphertexts() {
    let key = [42_u8; 32];

    let mut sender = ChaCha20Poly1305DataCipher::new(&key);

    let plaintext = b"same plaintext";

    let aad = b"session-123";

    let first = sender.encrypt(plaintext, aad).expect("first encryption");

    let second = sender.encrypt(plaintext, aad).expect("second encryption");

    assert_ne!(first, second, "two records must not reuse the same nonce");
}

#[test]
fn multiple_chacha_records_are_decrypted_in_order() {
    let key = [42_u8; 32];

    let mut sender = ChaCha20Poly1305DataCipher::new(&key);

    let mut receiver = ChaCha20Poly1305DataCipher::new(&key);

    let aad = b"session-records";

    for index in 0..100 {
        let message = format!("message-{index}");

        let ciphertext = sender
            .encrypt(message.as_bytes(), aad)
            .expect("encryption should succeed");

        let plaintext = receiver
            .decrypt(&ciphertext, aad)
            .expect("decryption should succeed");

        assert_eq!(plaintext, message.as_bytes());
    }
}

// ============================================================
// X25519
// ============================================================

#[test]
fn x25519_produces_same_shared_secret() {
    let alice = EphemeralKeyExchange::generate();

    let bob = EphemeralKeyExchange::generate();

    let alice_public = alice.public_key();

    let bob_public = bob.public_key();

    let alice_secret = alice.shared_secret(bob_public);

    let bob_secret = bob.shared_secret(alice_public);

    assert_eq!(
        alice_secret, bob_secret,
        "both peers must derive the same X25519 shared secret"
    );
}

#[test]
fn independent_x25519_exchanges_produce_different_secrets() {
    let alice1 = EphemeralKeyExchange::generate();

    let bob1 = EphemeralKeyExchange::generate();

    let alice1_public = alice1.public_key();

    let bob1_public = bob1.public_key();

    let secret1 = alice1.shared_secret(bob1_public);

    let secret1_b = bob1.shared_secret(alice1_public);

    assert_eq!(secret1, secret1_b);

    let alice2 = EphemeralKeyExchange::generate();

    let bob2 = EphemeralKeyExchange::generate();

    let alice2_public = alice2.public_key();

    let bob2_public = bob2.public_key();

    let secret2 = alice2.shared_secret(bob2_public);

    let secret2_b = bob2.shared_secret(alice2_public);

    assert_eq!(secret2, secret2_b);

    assert_ne!(
        secret1, secret2,
        "independent ephemeral exchanges should derive different secrets"
    );
}

// ============================================================
// HKDF
// ============================================================

#[test]
fn directional_keys_are_different() {
    let shared_secret = [7_u8; 32];

    let keys = derive_directional_keys(&shared_secret, "session-123", "chacha20-poly1305")
        .expect("key derivation should succeed");

    assert_ne!(
        keys.initiator_to_responder, keys.responder_to_initiator,
        "both directions must use different keys"
    );
}

#[test]
fn key_derivation_is_deterministic() {
    let shared_secret = [7_u8; 32];

    let first = derive_directional_keys(&shared_secret, "session-123", "chacha20-poly1305")
        .expect("first derivation");

    let second = derive_directional_keys(&shared_secret, "session-123", "chacha20-poly1305")
        .expect("second derivation");

    assert_eq!(first.initiator_to_responder, second.initiator_to_responder);

    assert_eq!(first.responder_to_initiator, second.responder_to_initiator);
}

#[test]
fn different_session_ids_produce_different_keys() {
    let shared_secret = [7_u8; 32];

    let session_a = derive_directional_keys(&shared_secret, "session-A", "chacha20-poly1305")
        .expect("session A derivation");

    let session_b = derive_directional_keys(&shared_secret, "session-B", "chacha20-poly1305")
        .expect("session B derivation");

    assert_ne!(
        session_a.initiator_to_responder,
        session_b.initiator_to_responder
    );

    assert_ne!(
        session_a.responder_to_initiator,
        session_b.responder_to_initiator
    );
}

#[test]
fn different_suites_produce_different_keys() {
    let shared_secret = [7_u8; 32];

    let aes = derive_directional_keys(&shared_secret, "session-123", "aes-256-gcm")
        .expect("AES derivation");

    let chacha = derive_directional_keys(&shared_secret, "session-123", "chacha20-poly1305")
        .expect("ChaCha derivation");

    assert_ne!(aes.initiator_to_responder, chacha.initiator_to_responder);

    assert_ne!(aes.responder_to_initiator, chacha.responder_to_initiator);
}
