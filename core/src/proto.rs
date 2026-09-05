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
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::grant::GrantStatus;
use crate::inventory::Channel;
use crate::registry::GrantRegistry;

pub const PROTO_VERSION: u32 = 2;

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
    Opening,
    Open,
    Expired,
    NeedsRevert,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLine {
    pub host: String,
    pub state: GrantState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub remaining_secs: Option<u64>,
    /// Present for needs-revert: the channels still awaiting revert.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stuck_channels: Option<Vec<Channel>>,
}

/// Renders every grant for a status response, in name order. Pure; the
/// daemon calls it inside its store read.
pub fn status_lines(registry: &GrantRegistry, now: SystemTime) -> Vec<GrantLine> {
    registry
        .statuses(now)
        .into_iter()
        .map(|(host, status)| {
            let host = host.to_string();
            match status {
                GrantStatus::Closed => GrantLine {
                    host,
                    state: GrantState::Closed,
                    remaining_secs: None,
                    stuck_channels: None,
                },
                GrantStatus::Opening => GrantLine {
                    host,
                    state: GrantState::Opening,
                    remaining_secs: None,
                    stuck_channels: None,
                },
                GrantStatus::Open { remaining } => GrantLine {
                    host,
                    state: GrantState::Open,
                    remaining_secs: Some(remaining.as_secs()),
                    stuck_channels: None,
                },
                GrantStatus::Expired => GrantLine {
                    host,
                    state: GrantState::Expired,
                    remaining_secs: None,
                    stuck_channels: None,
                },
                GrantStatus::NeedsRevert { channels } => GrantLine {
                    host,
                    state: GrantState::NeedsRevert,
                    remaining_secs: None,
                    stuck_channels: Some(channels),
                },
            }
        })
        .collect()
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
    /// A one-time credential for the operator (a BMC break-glass password, or
    /// a one-time VNC password). Carried to the CLI and shown once; never
    /// journaled.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub secret: Option<String>,
    /// How the CLI labels that secret, e.g. "break-glass BMC password" or
    /// "one-time VNC password". Absent, the CLI falls back to the BMC wording,
    /// so an older daemon's responses print exactly as before.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub secret_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseResult {
    Ok,
    Refused,
}

impl Response {
    pub fn ok() -> Response {
        Response {
            proto: PROTO_VERSION,
            result: ResponseResult::Ok,
            error: None,
            expires_at: None,
            outcome: None,
            grants: None,
            secret: None,
            secret_label: None,
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

#[cfg(test)]
mod tests;
