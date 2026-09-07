//! Pure helpers shared by the generic device channels (http, mqtt, serial).
//!
//! These channels drive arbitrary management surfaces from operator-supplied
//! request/command templates, so two disciplines from the vnc channel carry
//! over, adjusted for templates that are NOT shell commands:
//!
//! - **No placeholders at all.** The vnc channel substitutes a known
//!   placeholder set; the generic channels substitute nothing today, and the
//!   `{token}` vocabulary belongs to the coming `device` channel's own
//!   config. A `{name}` run in a generic template is therefore almost
//!   certainly a pasted-from-the-wrong-channel typo and is refused at load —
//!   lychgate would send it literally. (JSON bodies are safe: `{"key": ...}`
//!   and `{}` are not `{name}` runs, exactly as in the vnc scanner.)
//! - **A verify answer is a match, never a guess.** `match_state` maps a
//!   response body onto open/closed via two markers; a body matching neither
//!   is *unverifiable* and a body matching both is a broken marker pair —
//!   both are errors, because "I couldn't tell" reported as a state is how a
//!   fail-open hides.

use std::fmt;

use crate::channel::ChannelState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericTemplateError {
    /// A `{placeholder}` in a template that substitutes nothing.
    Placeholder(String),
}

impl fmt::Display for GenericTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenericTemplateError::Placeholder(p) => write!(
                f,
                "references placeholder {{{p}}}, but this channel substitutes nothing — \
                 lychgate would send it literally"
            ),
        }
    }
}

impl std::error::Error for GenericTemplateError {}

/// Refuses any `{name}` placeholder run (the vnc scanner's definition: one or
/// more of `[A-Za-z_]` between braces, not preceded by `$`).
pub fn forbid_placeholders(template: &str) -> Result<(), GenericTemplateError> {
    match crate::vnc::placeholders(template).into_iter().next() {
        Some(p) => Err(GenericTemplateError::Placeholder(p)),
        None => Ok(()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchError {
    /// The body matched neither marker: the state is unknown, which is an
    /// error, not a state.
    Neither,
    /// The body matched both markers: the marker pair cannot distinguish the
    /// states it claims to.
    Both,
}

impl fmt::Display for MatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchError::Neither => write!(
                f,
                "response matches neither the open nor the closed marker; the channel state is \
                 unverifiable"
            ),
            MatchError::Both => write!(
                f,
                "response matches both the open and the closed marker; the marker pair cannot \
                 distinguish the states"
            ),
        }
    }
}

impl std::error::Error for MatchError {}

/// Maps a response body onto a channel state via substring markers.
pub fn match_state(
    body: &str,
    open_marker: &str,
    closed_marker: &str,
) -> Result<ChannelState, MatchError> {
    match (body.contains(open_marker), body.contains(closed_marker)) {
        (true, true) => Err(MatchError::Both),
        (true, false) => Ok(ChannelState::Open),
        (false, true) => Ok(ChannelState::Closed),
        (false, false) => Err(MatchError::Neither),
    }
}

#[cfg(test)]
mod tests;
