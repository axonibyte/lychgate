//! Grant state machine, TTL policy, and inventory schema for lychgate.
//!
//! Everything here is pure logic with injected time: expiry is a property of
//! observation (`Grant::status(now)`), so no background thread is required
//! for a lapsed grant to read as expired.

pub mod approval;
pub mod authority;
pub mod bmc;
pub mod channel;
pub mod deadman;
pub mod fido2;
pub mod generic;
pub mod grant;
pub mod inventory;
pub mod password;
pub mod proto;
pub mod registry;
pub mod snapshot;
pub mod ssh;
pub mod totp;
pub mod tpm;
pub mod ttl;
pub mod vnc;

pub use approval::{parse_ssh_public_key, ApprovalError, ApprovalRequest, APPROVAL_NAMESPACE};
pub use authority::{
    ApprovalSpec, AuthKind, Authenticator, AuthenticatorSpec, Authority, AuthorityBody,
    AuthorityError, AuthorityModel, AuthoritySpec, Factor, FactorSpec, Missing, Outcome,
    ProfileSpec, WeightedFactor,
};
pub use channel::{
    apply_channels, reestablish_channels, renew_channels, revert_channels, ApplyCtx, ApplyOutcome,
    ChannelDriver, ChannelState, DriverError, DriverSet, ReestablishOutcome, RevertOutcome,
};
pub use fido2::{Alg, Fido2Credential, Fido2Error};
pub use generic::{match_state, GenericTemplateError, MatchError};
pub use grant::{Grant, GrantError, GrantStatus, PendingView, MAX_APPROVAL_WINDOW_SECS};
pub use inventory::{
    BmcConfig, BmcMethod, BmcTls, Channel, DeviceAlg, DeviceConfig, DeviceHttp, DeviceMqtt,
    DeviceSerial, DeviceTransportKind, Host, HostAccess, HttpConfig, HttpRequestSpec,
    HttpVerifySpec, Inventory, InventoryError, MqttAuth, MqttConfig, MqttMessageSpec,
    MqttVerifySpec, Os, SerialCmdSpec, SerialConfig, SerialVerifySpec, SigningSpec, SshConfig,
    VerifyMode, VncConfig,
};
pub use password::PasswordError;
pub use registry::{ExpiredGrant, ExpiredPending, GrantRegistry, RegistryError};
pub use snapshot::{GrantRecord, SnapshotError, StateDoc, STATE_VERSION};
pub use totp::{TotpError, TotpSecret};
pub use tpm::TpmError;
pub use ttl::{Ttl, TtlError, MAX_TTL_SECS, RENEWAL_WINDOW_SECS};
