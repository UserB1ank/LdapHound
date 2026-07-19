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

    /// User clicked the expand/collapse chevron of a tree node identified
    /// by its DN (lowercased). Toggle its expand state.
    ToggleNode(String),
    /// User selected a tree node to view its details on the right pane.
    SelectNode(usize),
}
