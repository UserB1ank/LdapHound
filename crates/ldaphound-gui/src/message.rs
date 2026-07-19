//! Elm messages: every user/runtime event that can mutate the app state.
//!
//! iced requires `Message: Clone + Send`. `ParseError` is not `Clone`, so
//! parse failures are stringified at the task boundary.

use std::path::PathBuf;

use ldaphound_core::Snapshot;

#[derive(Debug, Clone)]
pub enum Message {
    OpenFileClicked,
    FileSelected(Option<PathBuf>),
    ParseCompleted(Result<Snapshot, String>),

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
}
