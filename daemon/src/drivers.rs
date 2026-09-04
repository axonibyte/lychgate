//! Real channel drivers and the dead-man control. M5 status: the SSH-borne
//! channels and the dead-man are live; BMC and VNC are later milestones.

pub mod deadman;
pub(crate) mod remote;
pub mod ssh;
