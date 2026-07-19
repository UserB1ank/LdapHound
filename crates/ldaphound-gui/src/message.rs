//! Elm messages: every user/runtime event that can mutate [`super::app::App`].
//!
//! iced requires `Message: Clone + Send` so it can be forwarded to the
//! subscription system. `ParseError` is not `Clone` (it wraps `io::Error`),
//! so we convert parse failures to `String` at the task boundary.

use std::path::PathBuf;

use ldaphound_core::Snapshot;

#[derive(Debug, Clone)]
pub enum Message {
    /// User clicked "Open .dat".
    OpenFileClicked,
    /// File picker returned (None if user cancelled).
    FileSelected(Option<PathBuf>),
    /// Background parser finished. Errors are pre-stringified because
    /// `ParseError` is not `Clone`.
    ParseCompleted(Result<Snapshot, String>),
    /// User typed in the filter box.
    FilterChanged(String),
    /// User clicked an object row in the left pane.
    ObjectSelected(usize),
}
