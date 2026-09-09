use domain::PeerId;

use identity::{
    AuthenticatedPeer, PeerKeypair, PeerPublicKey, TrustStore, build_initiator, build_responder,
};

use snow::HandshakeState;

use crate::{SecureChannel, SecureChannelError};

pub struct SecureChannelPair {
    pub initiator: SecureChannel,

    pub responder: SecureChannel,

    pub authenticated_initiator: AuthenticatedPeer,

    pub authenticated_responder: AuthenticatedPeer,
}

fn noise_error(error: snow::Error) -> SecureChannelError {
    SecureChannelError::Noise(error.to_string())
}

fn complete_handshake(
    initiator: &mut HandshakeState,

    responder: &mut HandshakeState,
) -> Result<(), SecureChannelError> {
    let mut message = vec![0_u8; 65_535];

    let mut payload = vec![0_u8; 65_535];

    let len = initiator
        .write_message(&[], &mut message)
        .map_err(noise_error)?;

    responder
        .read_message(&message[..len], &mut payload)
        .map_err(noise_error)?;

    let len = responder
        .write_message(&[], &mut message)
        .map_err(noise_error)?;

    initiator
        .read_message(&message[..len], &mut payload)
        .map_err(noise_error)?;

    let len = initiator
        .write_message(&[], &mut message)
        .map_err(noise_error)?;

    responder
        .read_message(&message[..len], &mut payload)
        .map_err(noise_error)?;

    Ok(())
}

pub fn establish_in_memory(
    initiator_id: PeerId,
    initiator_keypair: &PeerKeypair,

    initiator_trust: &TrustStore,

    responder_id: PeerId,
    responder_keypair: &PeerKeypair,

    responder_trust: &TrustStore,
) -> Result<SecureChannelPair, SecureChannelError> {
    let mut initiator = build_initiator(initiator_keypair)
        .map_err(|error| SecureChannelError::Identity(error.to_string()))?;

    let mut responder = build_responder(responder_keypair)
        .map_err(|error| SecureChannelError::Identity(error.to_string()))?;

    complete_handshake(&mut initiator, &mut responder)?;

    let responder_public_key = PeerPublicKey::new(
        initiator
            .get_remote_static()
            .ok_or_else(|| SecureChannelError::Identity("missing responder static key".into()))?
            .to_vec(),
    );

    let initiator_public_key = PeerPublicKey::new(
        responder
            .get_remote_static()
            .ok_or_else(|| SecureChannelError::Identity("missing initiator static key".into()))?
            .to_vec(),
    );

    let initiator_hash = initiator.get_handshake_hash().to_vec();

    let responder_hash = responder.get_handshake_hash().to_vec();

    let authenticated_initiator = responder_trust
        .authenticate(initiator_id, initiator_public_key, responder_hash)
        .map_err(|error| SecureChannelError::Identity(error.to_string()))?;

    let authenticated_responder = initiator_trust
        .authenticate(responder_id, responder_public_key, initiator_hash)
        .map_err(|error| SecureChannelError::Identity(error.to_string()))?;

    let initiator_transport = initiator.into_transport_mode().map_err(noise_error)?;

    let responder_transport = responder.into_transport_mode().map_err(noise_error)?;

    Ok(SecureChannelPair {
        initiator: SecureChannel::new(initiator_transport),

        responder: SecureChannel::new(responder_transport),

        authenticated_initiator,

        authenticated_responder,
    })
}
