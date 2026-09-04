//! The wire protocol between lychgate and lychgated.
//!
//! Newline-delimited JSON over a local socket: one request line, one
//! response line, both carrying an explicit `proto` version. A request from
//! a newer protocol is refused with a message naming both versions, never
//! misparsed. Requests are capped at MAX_LINE_BYTES.
//!
//! Decoding is structural only; policy (TTL parsing, grant rules) is
//! enforced by `apply`, so the operator sees core's own error text, not a
//! transport paraphrase of it.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::grant::{CloseOutcome, GrantStatus};
use crate::registry::GrantRegistry;
use crate::ttl::Ttl;

pub const PROTO_VERSION: u32 = 1;

/// A request larger than this is refused unread. Nothing legitimate on this
/// protocol approaches it; without a cap, one connection could balloon the
/// daemon's memory.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Open { host: String, ttl: String },
    Close { host: String },
    Renew { host: String, ttl: String },
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    TooLarge {
        bytes: usize,
    },
    Malformed(String),
    /// Theirs is newer (or older) than ours; refused rather than guessed at.
    VersionMismatch {
        theirs: u32,
    },
    MissingField {
        op: &'static str,
        field: &'static str,
    },
    UnknownOp(String),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::TooLarge { bytes } => write!(
                f,
                "request of {bytes} bytes exceeds the {MAX_LINE_BYTES}-byte cap"
            ),
            ProtoError::Malformed(m) => write!(f, "malformed request: {m}"),
            ProtoError::VersionMismatch { theirs } => write!(
                f,
                "request speaks protocol {theirs}; this daemon speaks {PROTO_VERSION}"
            ),
            ProtoError::MissingField { op, field } => {
                write!(f, "{op} requires the {field:?} field")
            }
            ProtoError::UnknownOp(op) => write!(f, "unknown op {op:?}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// The version is probed leniently before anything else is parsed: a newer
/// protocol may carry fields this decoder refuses, and the refusal the
/// sender needs is "wrong version", not "unknown field".
#[derive(Deserialize)]
struct VersionProbe {
    proto: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    #[allow(dead_code)] // consumed by the version probe; named here so
    // deny_unknown_fields does not refuse it.
    proto: u32,
    op: String,
    host: Option<String>,
    ttl: Option<String>,
}

pub fn decode_request(line: &str) -> Result<Op, ProtoError> {
    if line.len() > MAX_LINE_BYTES {
        return Err(ProtoError::TooLarge { bytes: line.len() });
    }
    let probe: VersionProbe =
        serde_json::from_str(line).map_err(|e| ProtoError::Malformed(e.to_string()))?;
    match probe.proto {
        Some(v) if v != PROTO_VERSION => return Err(ProtoError::VersionMismatch { theirs: v }),
        // An absent version falls through to the strict parse below, whose
        // required `proto` field refuses it with the field named.
        _ => {}
    }
    let wire: RequestWire =
        serde_json::from_str(line).map_err(|e| ProtoError::Malformed(e.to_string()))?;

    let host = |op: &'static str| {
        wire.host
            .clone()
            .ok_or(ProtoError::MissingField { op, field: "host" })
    };
    let ttl = |op: &'static str| {
        wire.ttl
            .clone()
            .ok_or(ProtoError::MissingField { op, field: "ttl" })
    };
    match wire.op.as_str() {
        "open" => Ok(Op::Open {
            host: host("open")?,
            ttl: ttl("open")?,
        }),
        "close" => Ok(Op::Close {
            host: host("close")?,
        }),
        "renew" => Ok(Op::Renew {
            host: host("renew")?,
            ttl: ttl("renew")?,
        }),
        "status" => Ok(Op::Status),
        other => Err(ProtoError::UnknownOp(other.to_string())),
    }
}

pub fn encode_request(op: &Op) -> String {
    let (op_name, host, ttl) = match op {
        Op::Open { host, ttl } => ("open", Some(host), Some(ttl)),
        Op::Close { host } => ("close", Some(host), None),
        Op::Renew { host, ttl } => ("renew", Some(host), Some(ttl)),
        Op::Status => ("status", None, None),
    };
    let mut v = serde_json::json!({ "proto": PROTO_VERSION, "op": op_name });
    if let Some(host) = host {
        v["host"] = serde_json::json!(host);
    }
    if let Some(ttl) = ttl {
        v["ttl"] = serde_json::json!(ttl);
    }
    v.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantState {
    Closed,
    Open,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLine {
    pub host: String,
    pub state: GrantState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remaining_secs: Option<u64>,
}

/// Flat on the wire: {"proto":1,"result":"ok",...} or
/// {"proto":1,"result":"refused","error":"..."}.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub proto: u32,
    pub result: ResponseResult,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub grants: Option<Vec<GrantLine>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseResult {
    Ok,
    Refused,
}

impl Response {
    fn ok() -> Response {
        Response {
            proto: PROTO_VERSION,
            result: ResponseResult::Ok,
            error: None,
            expires_at: None,
            outcome: None,
            grants: None,
        }
    }

    pub fn refused(error: impl fmt::Display) -> Response {
        Response {
            error: Some(error.to_string()),
            result: ResponseResult::Refused,
            ..Response::ok()
        }
    }

    pub fn encode(&self) -> String {
        // Infallible for this shape: no non-string map keys, no floats.
        serde_json::to_string(self).expect("responses always serialize")
    }

    pub fn decode(line: &str) -> Result<Response, String> {
        serde_json::from_str(line).map_err(|e| e.to_string())
    }
}

/// A state change the daemon must journal. Refusals and status reads are
/// not transitions; a close that found the grant already closed is not one
/// either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Opened {
        host: String,
        ttl_secs: u64,
        expires_at: SystemTime,
    },
    Renewed {
        host: String,
        ttl_secs: u64,
        expires_at: SystemTime,
    },
    Closed {
        host: String,
    },
}

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Executes one operation against the registry. Pure: the daemon wraps this
/// in its store mutation and journals the returned transition after the
/// state commits.
pub fn apply(
    registry: &mut GrantRegistry,
    op: &Op,
    now: SystemTime,
) -> (Response, Option<Transition>) {
    match op {
        Op::Open { host, ttl } => {
            let ttl = match Ttl::parse(ttl) {
                Ok(t) => t,
                Err(e) => return (Response::refused(e), None),
            };
            match registry.open(host, now, &ttl) {
                Ok(expires_at) => (
                    Response {
                        expires_at: Some(epoch_secs(expires_at)),
                        ..Response::ok()
                    },
                    Some(Transition::Opened {
                        host: host.clone(),
                        ttl_secs: ttl.duration().as_secs(),
                        expires_at,
                    }),
                ),
                Err(e) => (Response::refused(e), None),
            }
        }
        Op::Renew { host, ttl } => {
            let ttl = match Ttl::parse(ttl) {
                Ok(t) => t,
                Err(e) => return (Response::refused(e), None),
            };
            match registry.renew(host, now, &ttl) {
                Ok(expires_at) => (
                    Response {
                        expires_at: Some(epoch_secs(expires_at)),
                        ..Response::ok()
                    },
                    Some(Transition::Renewed {
                        host: host.clone(),
                        ttl_secs: ttl.duration().as_secs(),
                        expires_at,
                    }),
                ),
                Err(e) => (Response::refused(e), None),
            }
        }
        Op::Close { host } => match registry.close(host) {
            Ok(CloseOutcome::WasOpen) => (
                Response {
                    outcome: Some("was-open".to_string()),
                    ..Response::ok()
                },
                Some(Transition::Closed { host: host.clone() }),
            ),
            Ok(CloseOutcome::AlreadyClosed) => (
                Response {
                    outcome: Some("already-closed".to_string()),
                    ..Response::ok()
                },
                // Nothing changed; nothing to journal.
                None,
            ),
            Err(e) => (Response::refused(e), None),
        },
        Op::Status => {
            let grants = registry
                .statuses(now)
                .into_iter()
                .map(|(host, status)| match status {
                    GrantStatus::Closed => GrantLine {
                        host: host.to_string(),
                        state: GrantState::Closed,
                        remaining_secs: None,
                    },
                    GrantStatus::Open { remaining } => GrantLine {
                        host: host.to_string(),
                        state: GrantState::Open,
                        remaining_secs: Some(remaining.as_secs()),
                    },
                    GrantStatus::Expired => GrantLine {
                        host: host.to_string(),
                        state: GrantState::Expired,
                        remaining_secs: None,
                    },
                })
                .collect();
            (
                Response {
                    grants: Some(grants),
                    ..Response::ok()
                },
                None,
            )
        }
    }
}

#[cfg(test)]
mod tests;
