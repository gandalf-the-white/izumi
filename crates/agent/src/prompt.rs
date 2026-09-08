use domain::NegotiationContext;

use crate::AdvisorError;

pub const CRYPTO_ADVISOR_PREAMBLE: &str = r#"
You are a cryptographic negotiation advisor.

Your only responsibility is to recommend one cryptographic suite
from the list of common suites supplied by the caller.

Rules:

- Recommend only a suite explicitly present in the common suite list.
- Never invent a cryptographic algorithm.
- Never recommend a suite outside the supplied list.
- Do not generate cryptographic keys.
- Do not perform encryption or decryption.
- Do not propose changes to the security policy.
- Base your recommendation only on the supplied metadata.
- Prefer higher-priority suites when there is no meaningful reason
  to choose otherwise.
- Keep the reason concise.
- Confidence must be between 0.0 and 1.0.

The recommendation is advisory only.
A deterministic security policy will validate the result.
"#;

pub fn build_crypto_advisor_prompt(context: &NegotiationContext) -> Result<String, AdvisorError> {
    let common = context.common_suite_descriptors();

    if common.is_empty() {
        return Err(AdvisorError::NoCommonSuite);
    }

    let mut prompt = String::from(
        "Select one cryptographic suite \
         from the following common suites:\n\n",
    );

    for descriptor in common {
        prompt.push_str(&format!(
            "- {:?}\n\
                 family: {:?}\n\
                 key_size_bits: {}\n\
                 nonce_size_bits: {}\n\
                 security_bits: {}\n\
                 aead: {}\n\
                 priority: {}\n\n",
            descriptor.id,
            descriptor.family,
            descriptor.key_size_bits,
            descriptor.nonce_size_bits,
            descriptor.security_bits,
            descriptor.aead,
            descriptor.priority,
        ));
    }

    Ok(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    use domain::{CryptoSuiteId, PeerCapabilities, PeerId};

    #[test]
    fn prompt_contains_only_common_suites() {
        let context = NegotiationContext::new(
            PeerCapabilities::new(
                PeerId::new("proxy-a"),
                vec![CryptoSuiteId::Aes256Gcm, CryptoSuiteId::ChaCha20Poly1305],
            ),
            PeerCapabilities::new(
                PeerId::new("proxy-b"),
                vec![CryptoSuiteId::ChaCha20Poly1305],
            ),
        );

        let prompt = build_crypto_advisor_prompt(&context).expect("prompt should be generated");

        assert!(prompt.contains("ChaCha20Poly1305"));

        assert!(!prompt.contains("- Aes256Gcm\n"));
    }
}
