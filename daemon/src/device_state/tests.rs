use super::*;

// Mutation notes (each observed failing): swap reserve_seq's bump-then-write
// to return before persisting → seq_survives_a_new_ledger_instance fails
// (the crash-reuse window); make read() return Default on corrupt →
// a_corrupt_ledger_refuses fails.

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "lychgate-device-state-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir.join("device-state.json")
}

const DEV: [u8; 16] = [7u8; 16];
const NONCE: [u8; 16] = [9u8; 16];

#[test]
fn seqs_are_strictly_monotonic_and_survive_a_new_ledger_instance() {
    let path = scratch("seq");
    let ledger = DeviceState::at(&path);
    assert_eq!(ledger.reserve_seq(&DEV).unwrap(), 1);
    assert_eq!(ledger.reserve_seq(&DEV).unwrap(), 2);
    // A fresh instance (a daemon restart) continues, never rewinds.
    let again = DeviceState::at(&path);
    assert_eq!(again.reserve_seq(&DEV).unwrap(), 3);
    // Independent devices count independently.
    assert_eq!(again.reserve_seq(&[8u8; 16]).unwrap(), 1);
}

#[test]
fn the_seq_is_persisted_before_it_is_returned() {
    // The crash-reuse window: after reserve_seq returns, a NEW instance
    // reading the file must already see the bump — the number was durable
    // before anyone could sign it into a token.
    let path = scratch("durable");
    let ledger = DeviceState::at(&path);
    let seq = ledger.reserve_seq(&DEV).unwrap();
    let fresh = DeviceState::at(&path);
    assert_eq!(fresh.reserve_seq(&DEV).unwrap(), seq + 1);
}

#[test]
fn open_nonce_round_trips_and_clears() {
    let path = scratch("nonce");
    let ledger = DeviceState::at(&path);
    assert_eq!(ledger.open_nonce(&DEV).unwrap(), None);
    ledger.set_open_nonce(&DEV, &NONCE).unwrap();
    assert_eq!(ledger.open_nonce(&DEV).unwrap(), Some(NONCE));
    // Survives a restart.
    assert_eq!(
        DeviceState::at(&path).open_nonce(&DEV).unwrap(),
        Some(NONCE)
    );
    ledger.clear_open_nonce(&DEV).unwrap();
    assert_eq!(ledger.open_nonce(&DEV).unwrap(), None);
}

#[test]
fn a_corrupt_ledger_refuses_rather_than_forgetting() {
    let path = scratch("corrupt");
    let ledger = DeviceState::at(&path);
    ledger.reserve_seq(&DEV).unwrap();
    fs::write(&path, "{ not json").unwrap();
    let err = ledger.reserve_seq(&DEV).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn a_future_ledger_version_refuses() {
    let path = scratch("version");
    fs::write(&path, r#"{"version": 99, "devices": {}}"#).unwrap();
    let err = DeviceState::at(&path).reserve_seq(&DEV).unwrap_err();
    assert!(err.to_string().contains("version 99"), "{err}");
}
