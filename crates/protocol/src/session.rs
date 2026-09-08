use domain::SessionId;
use uuid::Uuid;

pub fn generate_session_id() -> SessionId {
    SessionId::new(Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_session_ids_are_different() {
        let first = generate_session_id();

        let second = generate_session_id();

        assert_ne!(first, second);
    }

    #[test]
    fn generated_session_id_is_not_empty() {
        let session_id = generate_session_id();

        assert!(!session_id.as_str().is_empty());
    }
}
