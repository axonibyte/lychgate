use std::cell::RefCell;
use std::time::{Duration, UNIX_EPOCH};

use serde_json::{json, Value};

use lychgate_core::proto::{Op, PendingChallenge, Response};
use lychgate_core::{ApprovalError, ApprovalRequest, ApprovalSpec, AuthorityModel};

use crate::rpc::Server;
use crate::signer::Signer;
use crate::transport::Backend;

// A throwaway Ed25519 principal key (generated for the tests only; not used
// anywhere real). Its public half is embedded in `ai_model()` below.
const TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCOZkHrsPeFHOmyJXD3x8FsRrWpXYQWPtBQoQ9O/iWCWAAAAJii2DI2otgy
NgAAAAtzc2gtZWQyNTUxOQAAACCOZkHrsPeFHOmyJXD3x8FsRrWpXYQWPtBQoQ9O/iWCWA
AAAEAtPXTut9hsgBmNc9oblI022ru3IaeO+diZg9OooBQxlI5mQeuw94Uc6bIlcPfHwWxG
taldhBY+0FChD07+JYJYAAAAEWx5Y2hnYXRlLW1jcC10ZXN0AQIDBA==
-----END OPENSSH PRIVATE KEY-----";

const TEST_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII5mQeuw94Uc6bIlcPfHwWxGtaldhBY+0FChD07+JYJY lychgate-mcp-test";

fn signer() -> Signer {
    Signer::from_openssh(TEST_KEY).unwrap()
}

/// A policy whose only ed25519 authenticator is the test principal — the exact
/// verify path the daemon runs. The profile opts into MCP.
fn ai_model() -> AuthorityModel {
    let toml_text = format!(
        r#"
        [[authenticator]]
        id = "ai"
        kind = "ed25519"
        public-key = "{TEST_PUBKEY}"
        [[profile]]
        id = "ai-assisted"
        threshold = 1
        mcp = true
        factor = [ {{ authenticator = "ai", weight = 1 }} ]
        "#
    );
    let spec: ApprovalSpec = toml::from_str(&toml_text).unwrap();
    AuthorityModel::from_spec(&spec).unwrap()
}

fn a_request(nonce: u8) -> ApprovalRequest {
    ApprovalRequest::new(
        [nonce; 32],
        "db-01".to_string(),
        3600,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )
}

// --- the signing oracle -----------------------------------------------------

#[test]
fn the_ai_signature_verifies_through_the_daemons_ed25519_path() {
    let signer = signer();
    let model = ai_model();
    let req = a_request(7);
    let token = signer.sign_challenge(&req.challenge_string()).unwrap();
    assert_eq!(
        model.verify_ed25519(&req, &token).unwrap(),
        "ai",
        "the AI's token must satisfy the configured ai authenticator"
    );
}

#[test]
fn a_signature_for_another_challenge_is_refused() {
    // The oracle self-test: sign a DIFFERENT request's challenge and confirm the
    // verifier refuses it against this one (the challenge binding).
    let signer = signer();
    let model = ai_model();
    let this = a_request(7);
    let other = a_request(9);
    let wrong = signer.sign_challenge(&other.challenge_string()).unwrap();
    assert!(matches!(
        model.verify_ed25519(&this, &wrong),
        Err(ApprovalError::BadSignature)
    ));
}

// --- JSON-RPC framing -------------------------------------------------------

// A scriptable daemon: hands back canned responses in order, recording ops.
struct FakeBackend {
    responses: RefCell<Vec<Response>>,
    ops: RefCell<Vec<Op>>,
}
impl FakeBackend {
    fn new(responses: Vec<Response>) -> Self {
        Self {
            responses: RefCell::new(responses),
            ops: RefCell::new(Vec::new()),
        }
    }
}
impl Backend for FakeBackend {
    fn call(&self, op: &Op) -> anyhow::Result<Response> {
        self.ops.borrow_mut().push(op.clone());
        Ok(self.responses.borrow_mut().remove(0))
    }
}

fn server(responses: Vec<Response>) -> Server<FakeBackend> {
    Server::new(FakeBackend::new(responses), signer())
}

fn parse(line: &str) -> Value {
    serde_json::from_str(line).unwrap()
}

#[test]
fn initialize_reports_tools_capability() {
    let mut s = server(vec![]);
    let out = s
        .handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .expect("initialize gets a response");
    let v = parse(&out);
    assert_eq!(v["id"], 1);
    assert!(v["result"]["capabilities"]["tools"].is_object());
    assert_eq!(v["result"]["serverInfo"]["name"], "lychgate-mcp");
}

#[test]
fn tools_list_names_the_five_tools() {
    let mut s = server(vec![]);
    let out = s
        .handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .unwrap();
    let v = parse(&out);
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for expected in [
        "open_grant",
        "grant_status",
        "renew_grant",
        "close_grant",
        "access_handle",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
}

#[test]
fn a_notification_gets_no_response() {
    let mut s = server(vec![]);
    // No `id` -> a notification -> never answered.
    assert!(s
        .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .is_none());
}

#[test]
fn a_malformed_line_is_a_clean_error_not_a_panic() {
    let mut s = server(vec![]);
    let out = s
        .handle_line("{ this is not json")
        .expect("a parse error still replies");
    let v = parse(&out);
    assert_eq!(v["error"]["code"], -32700);
}

#[test]
fn an_unknown_tool_is_a_protocol_error() {
    let mut s = server(vec![]);
    let out = s
        .handle_line(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#)
        .unwrap();
    let v = parse(&out);
    assert_eq!(v["error"]["code"], -32602);
}

// --- open_grant contributes the AI factor -----------------------------------

#[test]
fn open_grant_signs_the_challenge_and_submits_the_ai_factor() {
    // The daemon returns a challenge on Open; the tool must sign THAT challenge
    // and submit it as the Approve token. We pin the challenge to a known
    // request and verify the recorded token against the daemon's ed25519 path.
    let req = a_request(5);
    let challenge = req.challenge_string();
    let open = Response {
        pending: Some(PendingChallenge {
            host: "db-01".into(),
            challenge: challenge.clone(),
            ttl_secs: 3600,
            requested_at: 1,
            approval_deadline: 2,
            profile: "ai-assisted".into(),
            weight: 0,
            threshold: 2,
            missing: vec!["ai".into(), "sysadmin".into()],
        }),
        ..Response::ok()
    };
    let approved = Response {
        pending: Some(PendingChallenge {
            host: "db-01".into(),
            challenge,
            ttl_secs: 3600,
            requested_at: 1,
            approval_deadline: 2,
            profile: "ai-assisted".into(),
            weight: 1,
            threshold: 2,
            missing: vec!["sysadmin".into()],
        }),
        ..Response::ok()
    };
    let backend = FakeBackend::new(vec![open, approved]);
    let signer = signer();

    let text = crate::tools::call(
        &backend,
        &signer,
        "open_grant",
        &json!({"host": "db-01", "ttl": "15m", "profile": "ai-assisted"}),
    )
    .map_err(|_| "tool failed")
    .unwrap();

    // The tool reported the AI factor accepted and the human still outstanding.
    assert!(text.contains("weight 1/2"), "got: {text}");
    assert!(text.contains("sysadmin"), "got: {text}");

    // The second op was an Approve whose token is a valid AI signature over the
    // challenge from Open — verified by the daemon's own ed25519 path.
    let ops = backend.ops.borrow();
    assert!(matches!(ops[0], Op::Open { .. }));
    match &ops[1] {
        Op::Approve { token, .. } => {
            assert_eq!(ai_model().verify_ed25519(&req, token).unwrap(), "ai");
        }
        other => panic!("expected Approve, got {other:?}"),
    }
}

#[test]
fn open_grant_surfaces_a_daemon_refusal() {
    // A non-mcp profile is refused by the daemon; the tool must surface it.
    let refused = Response::refused("profile \"humans\" is not reachable via the MCP front door");
    let backend = FakeBackend::new(vec![refused]);
    let err = crate::tools::call(
        &backend,
        &signer(),
        "open_grant",
        &json!({"host": "db-01", "ttl": "15m", "profile": "humans"}),
    );
    match err {
        Err(crate::tools::ToolError::Failed(msg)) => assert!(msg.contains("not reachable")),
        _ => panic!("expected a Failed tool error"),
    }
    // Only the Open was attempted — no signing/approve on a refused open.
    assert_eq!(backend.ops.borrow().len(), 1);
}
