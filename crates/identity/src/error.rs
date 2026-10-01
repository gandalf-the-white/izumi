use thiserror::Error;

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
