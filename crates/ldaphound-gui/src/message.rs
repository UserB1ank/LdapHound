//! Elm messages: every user/runtime event that can mutate the app state.
//!
//! iced requires `Message: Clone + Send`. `ParseError` is not `Clone`, so
//! parse failures are stringified at the task boundary.

use std::path::PathBuf;

use iced::widget::pane_grid;
use ldaphound_core::{Sid, Snapshot};

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
}

