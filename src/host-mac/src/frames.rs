// script-jail — src/host-mac/src/frames.rs
//
// JSONL frame types spoken between the guest agent and the host helper.
// Mirrors the TS `GuestFrame` discriminated union in
// src/shared/vsock-protocol.ts — keep them in sync. The host reads frames and
// sends the literal "go\n" handshake byte, which has no envelope.

use serde::{Deserialize, Serialize};

/// One JSONL frame.  Serde's internally-tagged adjacent-content
/// representation matches the wire format: every object has a `kind`
/// discriminator and the rest of the fields belong to the variant.
///
/// We derive both `Serialize` and `Deserialize` because the host helper's
/// pipeline is parse-on-the-vsock-thread / re-emit-on-stdout: re-emitting
/// gives us a canonical, validated form (a stray malformed line never
/// reaches the Node-side reader).
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Frame {
    Event(EventFrame),
    Handshake(HandshakeFrame),
    Error(ErrorFrame),
    Final(FinalFrame),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HandshakeFrame {
    pub phase: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorFrame {
    pub message: String,
    #[serde(default)]
    pub fatal: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FinalFrame {
    pub yaml: String,
}

/// Pass-through container.  The host helper does not interpret guest
/// events — it forwards them to the Node CLI which already has the normalizer
/// (src/lock/normalize.ts). Using `serde_json::Value`
/// here avoids duplicating the AttributedEvent schema on the Rust side.
#[derive(Debug, Deserialize, Serialize)]
pub struct EventFrame {
    #[serde(flatten)]
    pub event: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_frame() {
        let raw = r#"{"kind":"event","package":"left-pad","path":"/etc/passwd"}"#;
        let f: Frame = serde_json::from_str(raw).expect("parse");
        match f {
            Frame::Event(ev) => {
                assert!(ev.event.get("package").is_some());
                assert!(ev.event.get("path").is_some());
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn parse_handshake_frame() {
        let raw = r#"{"kind":"handshake","phase":"fetch_done"}"#;
        let f: Frame = serde_json::from_str(raw).expect("parse");
        match f {
            Frame::Handshake(h) => assert_eq!(h.phase, "fetch_done"),
            other => panic!("expected Handshake, got {other:?}"),
        }
    }

    #[test]
    fn parse_handshake_install_done() {
        let raw = r#"{"kind":"handshake","phase":"install_done"}"#;
        let f: Frame = serde_json::from_str(raw).expect("parse");
        match f {
            Frame::Handshake(h) => assert_eq!(h.phase, "install_done"),
            other => panic!("expected Handshake, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_frame_with_fatal() {
        let raw = r#"{"kind":"error","message":"boom","fatal":true}"#;
        let f: Frame = serde_json::from_str(raw).expect("parse");
        match f {
            Frame::Error(e) => {
                assert_eq!(e.message, "boom");
                assert!(e.fatal);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_frame_default_fatal_false() {
        let raw = r#"{"kind":"error","message":"oops"}"#;
        let f: Frame = serde_json::from_str(raw).expect("parse");
        match f {
            Frame::Error(e) => {
                assert_eq!(e.message, "oops");
                assert!(!e.fatal);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn parse_final_frame() {
        let raw = r#"{"kind":"final","yaml":"version: 1\n"}"#;
        let f: Frame = serde_json::from_str(raw).expect("parse");
        match f {
            Frame::Final(fin) => assert_eq!(fin.yaml, "version: 1\n"),
            other => panic!("expected Final, got {other:?}"),
        }
    }

    #[test]
    fn unknown_discriminator_errors() {
        let raw = r#"{"kind":"bogus","foo":1}"#;
        let result: Result<Frame, _> = serde_json::from_str(raw);
        assert!(result.is_err(), "expected error for unknown kind");
    }

    #[test]
    fn missing_required_field_errors() {
        // Handshake without `phase`.
        let raw = r#"{"kind":"handshake"}"#;
        let result: Result<Frame, _> = serde_json::from_str(raw);
        assert!(result.is_err(), "expected error for missing phase");
    }
}
