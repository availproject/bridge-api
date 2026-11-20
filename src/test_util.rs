//! Helpers that only the tests use.

use std::sync::{Arc, Mutex};
use tracing::subscriber::DefaultGuard;

/// Collects the log lines of one test.
///
/// tracing caches, per log call site, whether a subscriber wants the event. A test that reaches a
/// call site on a thread without a subscriber can cache "no" first, and then a test that captures
/// the log gets nothing from that call site. So every test that reaches a call site whose line
/// some test checks must capture the log too.
#[derive(Clone, Default)]
pub(crate) struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    /// Collects the log lines of the current thread until the guard is dropped.
    pub(crate) fn capture() -> (Self, DefaultGuard) {
        let log = Self::default();
        let writer = log.clone();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        (log, guard)
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
