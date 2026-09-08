use domain::PeerId;

use crate::PeerPublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    peer_id: PeerId,
    public_key: PeerPublicKey,
    handshake_hash: Vec<u8>,
}

impl AuthenticatedPeer {
    pub fn new(peer_id: PeerId, public_key: PeerPublicKey, handshake_hash: Vec<u8>) -> Self {
        Self {
            peer_id,
            public_key,
            handshake_hash,
        }
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn public_key(&self) -> &PeerPublicKey {
        &self.public_key
    }

    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }
}
