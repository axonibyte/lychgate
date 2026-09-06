//! A minimal, hand-rolled JSON-RPC 2.0 server over newline-delimited stdio —
//! the MCP stdio transport. Same spirit as the daemon's NDJSON wire: one JSON
//! object per line, no framework, `serde_json` only. Handles `initialize`,
//! `tools/list`, `tools/call`, `ping`, and ignores notifications (no id).

use serde_json::{json, Value};

use crate::signer::Signer;
use crate::tools::{self, ToolError};
use crate::transport::Backend;

/// The MCP protocol revision this server speaks back in `initialize`.
const PROTOCOL_VERSION: &str = "2024-11-05";

pub struct Server<B: Backend> {
    backend: B,
    signer: Signer,
}

impl<B: Backend> Server<B> {
    pub fn new(backend: B, signer: Signer) -> Self {
        Self { backend, signer }
    }

    /// Handle one JSON-RPC line. Returns the response line to write, or `None`
    /// for a notification (no `id`) or a blank line — those get no reply.
    pub fn handle_line(&mut self, line: &str) -> Option<String> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            // A parse error has no id to correlate; reply with null id per spec.
            Err(e) => {
                return Some(error_line(
                    Value::Null,
                    -32700,
                    &format!("parse error: {e}"),
                ))
            }
        };
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        // A request has an id; a notification does not and is never answered.
        let is_request = id.is_some();
        let outcome = self.dispatch(method, msg.get("params"));
        match (is_request, outcome) {
            (false, _) => None,
            (true, Ok(result)) => Some(ok_line(id.unwrap_or(Value::Null), result)),
            (true, Err((code, message))) => {
                Some(error_line(id.unwrap_or(Value::Null), code, &message))
            }
        }
    }

    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": { "name": "lychgate-mcp", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "tools": {} }
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools::schemas() })),
            "tools/call" => self.tools_call(params),
            other => Err((-32601, format!("method not found: {other}"))),
        }
    }

    fn tools_call(&self, params: Option<&Value>) -> Result<Value, (i64, String)> {
        let params = params.ok_or((-32602, "missing params".to_string()))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "missing tool name".to_string()))?;
        let empty = json!({});
        let args = params.get("arguments").unwrap_or(&empty);

        match tools::call(&self.backend, &self.signer, name, args) {
            Ok(text) => Ok(json!({ "content": [ { "type": "text", "text": text } ] })),
            // A ran-but-failed tool is a normal result flagged isError, so the
            // model sees the failure text rather than a transport error.
            Err(ToolError::Failed(msg)) => Ok(json!({
                "content": [ { "type": "text", "text": msg } ],
                "isError": true
            })),
            // An unknown tool is a protocol-level error.
            Err(ToolError::NotFound) => Err((-32602, format!("unknown tool: {name}"))),
        }
    }
}

fn ok_line(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_line(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}
