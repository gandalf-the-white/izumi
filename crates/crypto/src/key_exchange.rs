use rand::RngExt;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct EphemeralKeyExchange {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeyExchange {
    pub fn generate() -> Self {
        let mut rng = rand::rng();

        let secret_bytes: [u8; 32] = rng.random();

        let secret = StaticSecret::from(secret_bytes);

        let public = PublicKey::from(&secret);

        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn shared_secret(self, remote_public_key: [u8; 32]) -> [u8; 32] {
        let remote = PublicKey::from(remote_public_key);

        self.secret.diffie_hellman(&remote).to_bytes()
    }
}
