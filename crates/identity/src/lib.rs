mod authenticated_peer;
mod error;
mod keypair;
mod noise;
mod trust;

pub use authenticated_peer::AuthenticatedPeer;

pub use keypair::{PeerKeypair, PeerPublicKey, generate_keypair};

pub use trust::TrustStore;

pub use noise::{
    CompletedNoiseHandshake, build_initiator, build_responder, perform_handshake_in_memory,
};

pub use error::IdentityError;
