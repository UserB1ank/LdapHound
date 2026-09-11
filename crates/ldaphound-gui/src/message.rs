//! Elm messages: every user/runtime event that can mutate the app state.
//!
//! iced requires `Message: Clone + Send`. `ParseError` is not `Clone`, so
//! parse failures are stringified at the task boundary.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use iced::widget::pane_grid;
use ldaphound_core::{LdapGraph, Sid, Snapshot};

#[derive(Debug, Clone)]
pub struct LoadedDirectory {
    pub snapshot: Arc<Snapshot>,
    pub graph: Arc<LdapGraph>,
}

/// Secret text carried by iced messages. Its `Debug` representation is
/// always redacted so an API key cannot leak through event diagnostics.
#[derive(Clone, Default)]
pub struct SecretInput(String);

impl SecretInput {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    OpenFileClicked,
    FileSelected(Option<PathBuf>),
    ParseCompleted(Result<LoadedDirectory, String>),

    /// Toggle expand/collapse of a tree node identified by its DN.
    ToggleNode(String),
    /// Select a tree node to view its details.
    SelectNode(usize),

    /// Select an ACE row in the ACL grid (by index within the DACL).
    SelectAce(usize),
    /// Copy the given text to the system clipboard.
    CopyToClipboard(String),

    /// Switch the right pane between Attributes (0) and ACL (1).
    TabSelected(usize),

    /// User dragged the divider between sidebar and main panes.
    PaneResized(pane_grid::ResizeEvent),

    /// User typed in the sidebar filter box.
    FilterChanged(String),

    /// Jump to the object whose SID matches (right-click "Go to trustee"
    /// on an ACE card). Expands ancestors so the target is visible.
    SelectBySid(Sid),

    /// Toggle a trustee filter on the ACL tab. Empty string clears it.
    ToggleAclTrusteeFilter(String),
    /// Toggle a right filter on the ACL tab. Empty string clears it.
    ToggleAclRightFilter(String),

    /// AI analyst controls. Network access occurs only on AnalyzeClicked.
    AiSettingsToggled,
    AiApiKeyChanged(SecretInput),
    AiBaseUrlChanged(String),
    AiQuestionChanged(String),
    AiModelChanged(String),
    AiAnalyzeClicked,
    AiAnalysisCompleted(Result<String, String>),
}

#[cfg(test)]
mod tests {
    use super::{Message, SecretInput};

    #[test]
    fn api_key_is_redacted_from_message_debug_output() {
        let message = Message::AiApiKeyChanged(SecretInput::new("not-a-real-secret".into()));
        let debug = format!("{message:?}");
        assert!(!debug.contains("not-a-real-secret"));
        assert!(debug.contains("<redacted>"));
    }
}
