mod authenticated_peer;
mod keypair;
mod noise;
mod trust;

use thiserror::Error;

pub use authenticated_peer::AuthenticatedPeer;

pub use keypair::{PeerKeypair, PeerPublicKey, generate_keypair};

pub use noise::{
    CompletedNoiseHandshake, build_initiator, build_responder, perform_handshake_in_memory,
};

pub use trust::TrustStore;

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("unknown peer {0}")]
    UnknownPeer(String),

    #[error("peer public key does not match trusted key for {0}")]
    PublicKeyMismatch(String),

    #[error("Noise did not expose a remote static key")]
    MissingRemoteStaticKey,

    #[error("Noise error: {0}")]
    Noise(String),
}
