use hkdf::Hkdf;
use sha2::Sha256;

use crate::CryptoError;

pub struct DirectionalKeys {
    pub initiator_to_responder: [u8; 32],

    pub responder_to_initiator: [u8; 32],
}

pub fn derive_directional_keys(
    shared_secret: &[u8; 32],
    session_id: &str,
    suite_label: &str,
) -> Result<DirectionalKeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret);

    let mut i2r = [0_u8; 32];

    let mut r2i = [0_u8; 32];

    let info_i2r = format!("ai-socks-proxy/data/{suite_label}/initiator-to-responder");

    let info_r2i = format!("ai-socks-proxy/data/{suite_label}/responder-to-initiator");

    hkdf.expand(info_i2r.as_bytes(), &mut i2r)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    hkdf.expand(info_r2i.as_bytes(), &mut r2i)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(DirectionalKeys {
        initiator_to_responder: i2r,

        responder_to_initiator: r2i,
    })
}
