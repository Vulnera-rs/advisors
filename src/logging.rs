//! Logging configuration and initialization.
//!
//! This module handles setting up the `tracing` subscriber, potentially directing
//! logs to a file instead of stdout.

use crate::config::Config;
use tracing_appender::rolling;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use tracing_appender::non_blocking::WorkerGuard;

/// Initialize logging based on the provided configuration.
///
/// If `log_to_file` is enabled, logs will be written to daily files in `log_dir`.
/// Otherwise, logs are written to stdout.
///
/// Returns an optional `WorkerGuard`. This guard MUST be held for the duration of the
/// program (e.g., assigned to a variable in `main`). If dropped, log flushing may not complete.
pub fn init_logging(config: &Config) -> Option<WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if config.log_to_file {
        // Create a rolling file appender that rotates daily
        let file_appender = rolling::daily(&config.log_dir, "vulnera-advisor.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(non_blocking).with_ansi(false))
            .init();

        Some(guard)
    } else {
        // Standard stdout logging
        fmt()
            .with_env_filter(env_filter)
            .with_target(false) // Cleaner output for CLI
            .init();

        None
    }
}
