use domain::PeerId;

use identity::{PeerKeypair, PeerPublicKey, TrustStore, build_initiator, build_responder};

use snow::HandshakeState;

use tokio::net::TcpStream;

use secure_channel::SecureChannel;

use crate::{AuthenticatedConnection, FramedIo, TransportError};

const NOISE_MESSAGE_BUFFER_SIZE: usize = 65_535;

async fn write_noise_message(
    io: &mut FramedIo<TcpStream>,
    noise: &mut HandshakeState,
) -> Result<(), TransportError> {
    let mut buffer = vec![0_u8; NOISE_MESSAGE_BUFFER_SIZE];

    let written = noise
        .write_message(&[], &mut buffer)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    buffer.truncate(written);

    io.write_payload(&buffer).await
}

async fn read_noise_message(
    io: &mut FramedIo<TcpStream>,
    noise: &mut HandshakeState,
) -> Result<(), TransportError> {
    let message = io.read_payload().await?;

    let mut payload = vec![0_u8; NOISE_MESSAGE_BUFFER_SIZE];

    noise
        .read_message(&message, &mut payload)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    Ok(())
}

pub async fn perform_initiator_handshake(
    stream: TcpStream,
    local_keypair: &PeerKeypair,
    expected_peer_id: PeerId,
    trust_store: &TrustStore,
) -> Result<AuthenticatedConnection, TransportError> {
    let mut noise = build_initiator(local_keypair)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let mut io = FramedIo::new(stream);

    write_noise_message(&mut io, &mut noise).await?;

    read_noise_message(&mut io, &mut noise).await?;

    write_noise_message(&mut io, &mut noise).await?;

    if !noise.is_handshake_finished() {
        return Err(TransportError::Handshake(
            "initiator Noise XX handshake \
                 did not finish"
                .into(),
        ));
    }

    let remote_public_key = noise
        .get_remote_static()
        .ok_or_else(|| {
            TransportError::Authentication(
                "missing responder \
                         static key"
                    .into(),
            )
        })?
        .to_vec();

    let handshake_hash = noise.get_handshake_hash().to_vec();

    let authenticated_peer = trust_store
        .authenticate(
            expected_peer_id,
            PeerPublicKey::new(remote_public_key),
            handshake_hash,
        )
        .map_err(|error| TransportError::Authentication(error.to_string()))?;

    let transport = noise
        .into_transport_mode()
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let stream = io.into_inner();

    Ok(AuthenticatedConnection::new(
        stream,
        SecureChannel::new(transport),
        authenticated_peer,
    ))
}

pub async fn perform_responder_handshake(
    stream: TcpStream,
    local_keypair: &PeerKeypair,
    expected_peer_id: PeerId,
    trust_store: &TrustStore,
) -> Result<AuthenticatedConnection, TransportError> {
    let mut noise = build_responder(local_keypair)
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let mut io = FramedIo::new(stream);

    read_noise_message(&mut io, &mut noise).await?;

    write_noise_message(&mut io, &mut noise).await?;

    read_noise_message(&mut io, &mut noise).await?;

    if !noise.is_handshake_finished() {
        return Err(TransportError::Handshake(
            "responder Noise XX handshake \
                 did not finish"
                .into(),
        ));
    }

    let remote_public_key = noise
        .get_remote_static()
        .ok_or_else(|| {
            TransportError::Authentication(
                "missing initiator \
                         static key"
                    .into(),
            )
        })?
        .to_vec();

    let handshake_hash = noise.get_handshake_hash().to_vec();

    let authenticated_peer = trust_store
        .authenticate(
            expected_peer_id,
            PeerPublicKey::new(remote_public_key),
            handshake_hash,
        )
        .map_err(|error| TransportError::Authentication(error.to_string()))?;

    let transport = noise
        .into_transport_mode()
        .map_err(|error| TransportError::Handshake(error.to_string()))?;

    let stream = io.into_inner();

    Ok(AuthenticatedConnection::new(
        stream,
        SecureChannel::new(transport),
        authenticated_peer,
    ))
}
