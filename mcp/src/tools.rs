//! The MCP tools the AI front door exposes, translated to daemon ops. `open`
//! auto-contributes the AI factor (it signs the challenge it just received);
//! `approve` is deliberately absent — the daemon only returns a challenge from
//! `open`, so the AI can only sign a grant it initiated, which is the whole
//! point of a front door. Access handles are non-secret (state + remaining);
//! one-time-secret delivery to the AI is a deferred design (see ROADMAP).

use serde_json::{json, Value};

use lychgate_core::proto::{GrantState, Op, Response, ResponseResult};

use crate::signer::Signer;
use crate::transport::Backend;

pub enum ToolError {
    /// No such tool — a JSON-RPC protocol error.
    NotFound,
    /// The tool ran but failed — surfaced to the model as an `isError` result.
    Failed(String),
}

/// The tool catalogue for `tools/list`.
pub fn schemas() -> Vec<Value> {
    let host = json!({"type": "string", "description": "The inventory host name."});
    let ttl = json!({"type": "string", "description": "Time to live, e.g. 90s, 15m, 2h (capped at 24h)."});
    vec![
        json!({
            "name": "open_grant",
            "description": "Request a break-glass grant on a host and contribute the AI factor. \
                Returns a pending challenge that human factors must still satisfy out of band \
                (unless the profile is satisfied by the AI alone). The profile must be reachable \
                over MCP (mcp = true) or the daemon refuses.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": host,
                    "ttl": ttl,
                    "profile": {"type": "string", "description": "Approval profile to open under (omit if the host permits exactly one)."}
                },
                "required": ["host", "ttl"]
            }
        }),
        json!({
            "name": "grant_status",
            "description": "Report the state of every grant, or one host's.",
            "inputSchema": {
                "type": "object",
                "properties": {"host": {"type": "string", "description": "Limit to this host (optional)."}}
            }
        }),
        json!({
            "name": "renew_grant",
            "description": "Extend an open grant's TTL (accepted only near expiry).",
            "inputSchema": {
                "type": "object",
                "properties": {"host": host, "ttl": ttl},
                "required": ["host", "ttl"]
            }
        }),
        json!({
            "name": "close_grant",
            "description": "Close a host's grant and revert everything it opened.",
            "inputSchema": {
                "type": "object",
                "properties": {"host": {"type": "string", "description": "The inventory host name."}},
                "required": ["host"]
            }
        }),
        json!({
            "name": "access_handle",
            "description": "The current, non-secret access handle for a host: whether the grant is \
                open and how long it has left. One-time secrets (VNC/BMC passwords) are not \
                delivered over MCP.",
            "inputSchema": {
                "type": "object",
                "properties": {"host": {"type": "string", "description": "The inventory host name."}},
                "required": ["host"]
            }
        }),
    ]
}

pub fn call(
    backend: &dyn Backend,
    signer: &Signer,
    name: &str,
    args: &Value,
) -> Result<String, ToolError> {
    match name {
        "open_grant" => open_grant(backend, signer, args),
        "grant_status" => grant_status(backend, args),
        "renew_grant" => renew_grant(backend, args),
        "close_grant" => close_grant(backend, args),
        "access_handle" => access_handle(backend, args),
        _ => Err(ToolError::NotFound),
    }
}

fn req_str(args: &Value, key: &str) -> Result<String, ToolError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ToolError::Failed(format!("missing required argument {key:?}")))
}

fn opt_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn failed(e: anyhow::Error) -> ToolError {
    ToolError::Failed(e.to_string())
}

fn open_grant(backend: &dyn Backend, signer: &Signer, args: &Value) -> Result<String, ToolError> {
    let host = req_str(args, "host")?;
    let ttl = req_str(args, "ttl")?;
    let profile = opt_str(args, "profile");

    let open = backend
        .call(&Op::Open {
            host: host.clone(),
            ttl,
            profile,
        })
        .map_err(failed)?;
    if open.result == ResponseResult::Refused {
        return Err(ToolError::Failed(format!(
            "open refused: {}",
            open.error.unwrap_or_default()
        )));
    }
    let Some(pending) = open.pending else {
        // No challenge to sign (e.g. a dry-run daemon): report what we have.
        return Ok(describe_open_response(&host, &open));
    };

    // Auto-contribute the AI factor by signing the challenge we just received.
    let token = signer
        .sign_challenge(&pending.challenge)
        .map_err(|e| ToolError::Failed(format!("signing the challenge failed: {e}")))?;
    let approved = backend
        .call(&Op::Approve {
            host: host.clone(),
            token,
        })
        .map_err(failed)?;

    // When the grant is still pending, the human factors are added out of band
    // by signing the SAME challenge — so surface it (it is public) for relay.
    let challenge_line = format!(
        "\nTo add a human factor, sign this challenge and approve it on the operator socket:\n{}",
        pending.challenge
    );
    Ok(match approved.result {
        // The AI factor was accepted; report the resulting state.
        ResponseResult::Ok => match &approved.pending {
            Some(p) => format!(
                "Requested {host:?} under profile {:?}. The AI factor was accepted \
                 (weight {}/{}). Still awaiting out-of-band approval: {}.{}",
                p.profile,
                p.weight,
                p.threshold,
                render_missing(&p.missing),
                challenge_line,
            ),
            None => format!(
                "Requested {host:?} under profile {:?}. The AI factor met the threshold — \
                 the grant is OPEN{}.",
                pending.profile,
                expiry_suffix(&approved),
            ),
        },
        // The AI factor was not accepted here (it may not be part of this
        // profile). The request still stands for human approval.
        ResponseResult::Refused => format!(
            "Requested {host:?} under profile {:?} (weight {}/{}). The AI factor was not \
             accepted for this profile ({}). Awaiting out-of-band approval: {}.{}",
            pending.profile,
            pending.weight,
            pending.threshold,
            approved.error.unwrap_or_default(),
            render_missing(&pending.missing),
            challenge_line,
        ),
    })
}

fn grant_status(backend: &dyn Backend, args: &Value) -> Result<String, ToolError> {
    let only = opt_str(args, "host");
    let resp = backend.call(&Op::Status).map_err(failed)?;
    let grants = resp.grants.unwrap_or_default();
    let lines: Vec<String> = grants
        .iter()
        .filter(|g| only.as_deref().is_none_or(|h| h == g.host))
        .map(render_grant_line)
        .collect();
    if lines.is_empty() {
        return Ok(match only {
            Some(h) => format!("No grant for host {h:?}."),
            None => "No grants.".to_string(),
        });
    }
    Ok(lines.join("\n"))
}

fn renew_grant(backend: &dyn Backend, args: &Value) -> Result<String, ToolError> {
    let host = req_str(args, "host")?;
    let ttl = req_str(args, "ttl")?;
    let resp = backend
        .call(&Op::Renew {
            host: host.clone(),
            ttl,
        })
        .map_err(failed)?;
    match resp.result {
        ResponseResult::Ok => Ok(format!("Renewed {host:?}{}.", expiry_suffix(&resp))),
        ResponseResult::Refused => Err(ToolError::Failed(format!(
            "renew refused: {}",
            resp.error.unwrap_or_default()
        ))),
    }
}

fn close_grant(backend: &dyn Backend, args: &Value) -> Result<String, ToolError> {
    let host = req_str(args, "host")?;
    let resp = backend
        .call(&Op::Close { host: host.clone() })
        .map_err(failed)?;
    match resp.result {
        ResponseResult::Ok => Ok(format!(
            "Closed {host:?} ({}).",
            resp.outcome.as_deref().unwrap_or("reverted")
        )),
        ResponseResult::Refused => Err(ToolError::Failed(format!(
            "close refused: {}",
            resp.error.unwrap_or_default()
        ))),
    }
}

fn access_handle(backend: &dyn Backend, args: &Value) -> Result<String, ToolError> {
    let host = req_str(args, "host")?;
    let resp = backend.call(&Op::Status).map_err(failed)?;
    let grants = resp.grants.unwrap_or_default();
    match grants.iter().find(|g| g.host == host) {
        None => Ok(format!("No grant for host {host:?}.")),
        Some(g) => match g.state {
            GrantState::Open => Ok(format!(
                "{host:?} is OPEN{}. Use your configured access (e.g. SSH with your own key); \
                 one-time secrets are not delivered over MCP.",
                match g.remaining_secs {
                    Some(s) => format!(", {s}s remaining"),
                    None => String::new(),
                }
            )),
            _ => Ok(format!(
                "{host:?} is {} — no usable access handle yet.",
                render_state(&g.state)
            )),
        },
    }
}

// --- rendering helpers ------------------------------------------------------

fn render_missing(missing: &[String]) -> String {
    if missing.is_empty() {
        "nothing (threshold met)".to_string()
    } else {
        missing.join(", ")
    }
}

fn expiry_suffix(resp: &Response) -> String {
    match resp.expires_at {
        Some(e) => format!(" until epoch {e}"),
        None => String::new(),
    }
}

fn render_state(state: &GrantState) -> &'static str {
    match state {
        GrantState::Closed => "closed",
        GrantState::AwaitingApproval => "awaiting approval",
        GrantState::ApprovalExpired => "approval-expired",
        GrantState::Opening => "opening",
        GrantState::Open => "open",
        GrantState::Expired => "expired",
        GrantState::NeedsRevert => "needs-revert",
    }
}

fn render_grant_line(g: &lychgate_core::proto::GrantLine) -> String {
    match g.remaining_secs {
        Some(s) => format!("{}: {} ({s}s remaining)", g.host, render_state(&g.state)),
        None => format!("{}: {}", g.host, render_state(&g.state)),
    }
}

fn describe_open_response(host: &str, resp: &Response) -> String {
    if resp.expires_at.is_some() {
        format!("{host:?} is OPEN{}.", expiry_suffix(resp))
    } else {
        format!("Requested {host:?}.")
    }
}
