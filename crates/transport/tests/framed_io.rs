use secure_channel::MAX_ENCRYPTED_FRAME_SIZE;

use tokio::io::AsyncWriteExt;

use transport::{FramedIo, TransportError};

#[tokio::test]
async fn payload_roundtrip_works() {
    let (stream_a, stream_b) = tokio::io::duplex(1024);

    let mut writer = FramedIo::new(stream_a);

    let mut reader = FramedIo::new(stream_b);

    let payload = b"hello proxy";

    writer
        .write_payload(payload)
        .await
        .expect("payload should be written");

    let received = reader.read_payload().await.expect("payload should be read");

    assert_eq!(received, payload);
}

#[tokio::test]
async fn fragmented_payload_is_reassembled() {
    let (mut writer, reader) = tokio::io::duplex(1024);

    let payload = b"fragmented-message";

    let header = (payload.len() as u32).to_be_bytes();

    let task = tokio::spawn(async move {
        writer.write_all(&header[..2]).await.unwrap();

        writer.write_all(&header[2..]).await.unwrap();

        writer.write_all(&payload[..5]).await.unwrap();

        writer.write_all(&payload[5..]).await.unwrap();
    });

    let mut framed = FramedIo::new(reader);

    let received = framed.read_payload().await.expect(
        "fragmented payload \
                 should be reconstructed",
    );

    task.await.unwrap();

    assert_eq!(received, payload);
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_payload_read() {
    let (mut attacker, victim) = tokio::io::duplex(64);

    let malicious_length = (MAX_ENCRYPTED_FRAME_SIZE as u32) + 1;

    attacker
        .write_all(&malicious_length.to_be_bytes())
        .await
        .unwrap();

    let mut framed = FramedIo::new(victim);

    let result = framed.read_payload().await;

    assert!(matches!(result, Err(TransportError::FrameTooLarge { .. })));
}

#[tokio::test]
async fn empty_frame_is_rejected() {
    let (mut attacker, victim) = tokio::io::duplex(64);

    attacker.write_all(&0_u32.to_be_bytes()).await.unwrap();

    let mut framed = FramedIo::new(victim);

    let result = framed.read_payload().await;

    assert!(matches!(result, Err(TransportError::EmptyFrame)));
}
