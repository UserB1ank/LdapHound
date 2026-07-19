//! Background task wrappers around `ldaphound_core::Snapshot`.
//!
//! iced `Task`s must return `Send + 'static` data. `Snapshot` is fully owned
//! (no mmap borrow), so it moves freely across threads. Parsing is CPU-bound
//! synchronous work, so we run it on `tokio::task::spawn_blocking` to avoid
//! stalling the async reactor.

use std::path::PathBuf;

use iced::Task;
use ldaphound_core::Snapshot;

use crate::message::Message;

/// Spawn the snapshot parser on a background thread, then deliver the result
/// as [`Message::ParseCompleted`]. Errors are stringified because
/// `ParseError` is not `Clone` (and iced requires `Message: Clone`).
pub fn parse_snapshot(path: PathBuf) -> Task<Message> {
    Task::perform(
        async move {
            let result: Result<Snapshot, String> = (|| {
                let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
                // SAFETY: read-only mapping of a file we just opened.
                // `Snapshot` copies its data out of the mapping, so the
                // returned value does not alias the mmap.
                let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| e.to_string())?;
                Snapshot::parse_bytes(&mmap).map_err(|e| e.to_string())
            })();
            // tokio's spawn_blocking keeps the CPU work off the async reactor.
            match tokio::task::spawn_blocking(move || result).await {
                Ok(r) => r,
                Err(join_err) => Err(join_err.to_string()),
            }
        },
        Message::ParseCompleted,
    )
}
