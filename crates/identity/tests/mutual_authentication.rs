use domain::PeerId;

use identity::{TrustStore, generate_keypair, perform_handshake_in_memory};

#[test]
fn noise_xx_exchanges_static_public_keys() {
    let proxy_a = generate_keypair().expect("proxy A keypair");

    let proxy_b = generate_keypair().expect("proxy B keypair");

    let handshake =
        perform_handshake_in_memory(&proxy_a, &proxy_b).expect("handshake should succeed");

    assert_eq!(handshake.initiator_remote_key, *proxy_b.public_key());

    assert_eq!(handshake.responder_remote_key, *proxy_a.public_key());
}

#[test]
fn both_peers_have_same_handshake_hash() {
    let proxy_a = generate_keypair().unwrap();

    let proxy_b = generate_keypair().unwrap();

    let handshake = perform_handshake_in_memory(&proxy_a, &proxy_b).unwrap();

    assert_eq!(
        handshake.initiator_handshake_hash,
        handshake.responder_handshake_hash,
    );
}

#[test]
fn trusted_proxies_authenticate_each_other() {
    let proxy_a_id = PeerId::new("proxy-a");

    let proxy_b_id = PeerId::new("proxy-b");

    let proxy_a = generate_keypair().unwrap();

    let proxy_b = generate_keypair().unwrap();

    let mut trust_a = TrustStore::new();

    let mut trust_b = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), proxy_b.public_key().clone());

    trust_b.trust(proxy_a_id.clone(), proxy_a.public_key().clone());

    let handshake = perform_handshake_in_memory(&proxy_a, &proxy_b).unwrap();

    let authenticated_b = trust_a
        .authenticate(
            proxy_b_id,
            handshake.initiator_remote_key,
            handshake.initiator_handshake_hash,
        )
        .expect("proxy B should authenticate");

    let authenticated_a = trust_b
        .authenticate(
            proxy_a_id,
            handshake.responder_remote_key,
            handshake.responder_handshake_hash,
        )
        .expect("proxy A should authenticate");

    assert_eq!(authenticated_b.peer_id().as_str(), "proxy-b");

    assert_eq!(authenticated_a.peer_id().as_str(), "proxy-a");
}

#[test]
fn attacker_claiming_trusted_peer_id_is_rejected() {
    let proxy_a = generate_keypair().unwrap();

    let real_proxy_b = generate_keypair().unwrap();

    let attacker = generate_keypair().unwrap();

    let proxy_b_id = PeerId::new("proxy-b");

    let mut trust_a = TrustStore::new();

    trust_a.trust(proxy_b_id.clone(), real_proxy_b.public_key().clone());

    let handshake = perform_handshake_in_memory(&proxy_a, &attacker)
        .expect("Noise handshake itself can succeed");

    let result = trust_a.authenticate(
        proxy_b_id,
        handshake.initiator_remote_key,
        handshake.initiator_handshake_hash,
    );

    assert!(matches!(
        result,
        Err(identity::IdentityError::PublicKeyMismatch(_))
    ));
}
