//! Background task wrappers around `ldaphound_core::Snapshot`.
//!
//! iced `Task`s must return `Send + 'static` data. `Snapshot` is fully owned
//! (no mmap borrow), so it moves freely across threads. Parsing is CPU-bound
//! synchronous work, so we run it on `tokio::task::spawn_blocking` to avoid
//! stalling the async reactor.

use std::path::PathBuf;
use std::sync::Arc;

use iced::Task;
use ldaphound_core::ai::{AiAnalyzer, AiConfig};
use ldaphound_core::{LdapGraph, Snapshot};

use crate::message::{LoadedDirectory, Message};

/// Spawn the snapshot parser on a background thread, then deliver the result
/// as [`Message::ParseCompleted`]. `load_bytes` auto-detects the format
/// (ADExplorer `.dat` binary or LDIF text from `ldapsearch`). Errors are
/// stringified because `ParseError` is not `Clone` (and iced requires
/// `Message: Clone`).
pub fn parse_snapshot(path: PathBuf) -> Task<Message> {
    Task::perform(
        async move {
            let result: Result<LoadedDirectory, String> = (|| {
                let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
                // SAFETY: read-only mapping of a file we just opened.
                // `Snapshot` copies its data out of the mapping, so the
                // returned value does not alias the mmap.
                let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| e.to_string())?;
                let snapshot = Arc::new(Snapshot::load_bytes(&mmap).map_err(|e| e.to_string())?);
                let graph = Arc::new(LdapGraph::from_snapshot(&snapshot));
                Ok(LoadedDirectory { snapshot, graph })
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

/// Run the blocking HTTPS + function-calling loop away from iced's async
/// reactor. The API key is read inside the worker and never enters App state.
pub fn analyze_graph(
    graph: Arc<LdapGraph>,
    question: String,
    model: String,
    focus_node: Option<usize>,
) -> Task<Message> {
    Task::perform(
        async move {
            match tokio::task::spawn_blocking(move || {
                let mut config = AiConfig::from_env().map_err(|error| error.to_string())?;
                config.set_model(model);
                let analyzer = AiAnalyzer::new(config).map_err(|error| error.to_string())?;
                analyzer
                    .analyze(&graph, &question, focus_node)
                    .map_err(|error| error.to_string())
            })
            .await
            {
                Ok(result) => result,
                Err(join_error) => Err(join_error.to_string()),
            }
        },
        Message::AiAnalysisCompleted,
    )
}
