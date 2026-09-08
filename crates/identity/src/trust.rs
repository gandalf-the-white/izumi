use std::collections::HashMap;

use domain::PeerId;

use crate::{AuthenticatedPeer, IdentityError, PeerPublicKey};

#[derive(Debug, Default)]
pub struct TrustStore {
    peers: HashMap<PeerId, PeerPublicKey>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(&mut self, peer_id: PeerId, public_key: PeerPublicKey) {
        self.peers.insert(peer_id, public_key);
    }

    pub fn verify(
        &self,
        peer_id: &PeerId,
        received_key: &PeerPublicKey,
    ) -> Result<(), IdentityError> {
        let Some(expected) = self.peers.get(peer_id) else {
            return Err(IdentityError::UnknownPeer(peer_id.as_str().to_owned()));
        };

        if expected != received_key {
            return Err(IdentityError::PublicKeyMismatch(
                peer_id.as_str().to_owned(),
            ));
        }

        Ok(())
    }

    pub fn authenticate(
        &self,
        peer_id: PeerId,
        received_key: PeerPublicKey,
        handshake_hash: Vec<u8>,
    ) -> Result<AuthenticatedPeer, IdentityError> {
        self.verify(&peer_id, &received_key)?;

        Ok(AuthenticatedPeer::new(
            peer_id,
            received_key,
            handshake_hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    #[test]
    fn trusted_key_is_accepted() {
        let keypair = generate_keypair().unwrap();

        let mut store = TrustStore::new();

        let peer_id = PeerId::new("proxy-b");

        store.trust(peer_id.clone(), keypair.public_key().clone());

        assert!(store.verify(&peer_id, keypair.public_key(),).is_ok());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let expected = generate_keypair().unwrap();

        let attacker = generate_keypair().unwrap();

        let mut store = TrustStore::new();

        let peer_id = PeerId::new("proxy-b");

        store.trust(peer_id.clone(), expected.public_key().clone());

        assert!(matches!(
            store.verify(&peer_id, attacker.public_key(),),
            Err(IdentityError::PublicKeyMismatch(_))
        ));
    }
}
