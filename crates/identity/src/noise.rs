use snow::{Builder, HandshakeState, params::NoiseParams};

use crate::{IdentityError, NOISE_PATTERN, PeerKeypair, PeerPublicKey};

const NOISE_PROLOGUE: &[u8] = b"ai-socks-proxy/protocol-v1";

fn noise_error(error: snow::Error) -> IdentityError {
    IdentityError::Noise(error.to_string())
}

pub fn build_initiator(keypair: &PeerKeypair) -> Result<HandshakeState, IdentityError> {
    let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_error)?;

    Builder::new(params)
        .local_private_key(keypair.private_key().as_bytes())
        .map_err(noise_error)?
        .prologue(NOISE_PROLOGUE)
        .map_err(noise_error)?
        .build_initiator()
        .map_err(noise_error)
}

pub fn build_responder(keypair: &PeerKeypair) -> Result<HandshakeState, IdentityError> {
    let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_error)?;

    Builder::new(params)
        .local_private_key(keypair.private_key().as_bytes())
        .map_err(noise_error)?
        .prologue(NOISE_PROLOGUE)
        .map_err(noise_error)?
        .build_responder()
        .map_err(noise_error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedNoiseHandshake {
    pub initiator_remote_key: PeerPublicKey,

    pub responder_remote_key: PeerPublicKey,

    pub initiator_handshake_hash: Vec<u8>,

    pub responder_handshake_hash: Vec<u8>,
}

pub fn perform_handshake_in_memory(
    initiator_keypair: &PeerKeypair,

    responder_keypair: &PeerKeypair,
) -> Result<CompletedNoiseHandshake, IdentityError> {
    let mut initiator = build_initiator(initiator_keypair)?;

    let mut responder = build_responder(responder_keypair)?;

    let mut message = vec![0_u8; 65535];

    let mut payload = vec![0_u8; 65535];

    // XX message 1
    let len = initiator
        .write_message(&[], &mut message)
        .map_err(noise_error)?;

    responder
        .read_message(&message[..len], &mut payload)
        .map_err(noise_error)?;

    // XX message 2
    let len = responder
        .write_message(&[], &mut message)
        .map_err(noise_error)?;

    initiator
        .read_message(&message[..len], &mut payload)
        .map_err(noise_error)?;

    // XX message 3
    let len = initiator
        .write_message(&[], &mut message)
        .map_err(noise_error)?;

    responder
        .read_message(&message[..len], &mut payload)
        .map_err(noise_error)?;

    if !initiator.is_handshake_finished() || !responder.is_handshake_finished() {
        return Err(IdentityError::Noise(
            "Noise XX handshake did not finish".into(),
        ));
    }

    let initiator_remote_key = initiator
        .get_remote_static()
        .ok_or(IdentityError::MissingRemoteStaticKey)?
        .to_vec();

    let responder_remote_key = responder
        .get_remote_static()
        .ok_or(IdentityError::MissingRemoteStaticKey)?
        .to_vec();

    let initiator_handshake_hash = initiator.get_handshake_hash().to_vec();

    let responder_handshake_hash = responder.get_handshake_hash().to_vec();

    Ok(CompletedNoiseHandshake {
        initiator_remote_key: PeerPublicKey::new(initiator_remote_key),

        responder_remote_key: PeerPublicKey::new(responder_remote_key),

        initiator_handshake_hash,

        responder_handshake_hash,
    })
}
