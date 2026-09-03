//! Shared vocabulary for Eris: the library error type and cross-crate constants.

/// Default path of the daemon's admin control socket. Shared by the daemon
/// (server) and the CLI (client) so they agree without duplication.
pub const DEFAULT_ADMIN_SOCKET: &str = "/run/eris/admin.sock";

/// Result alias for fallible library calls.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by Eris library functions.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Invalid or unreadable configuration.
    #[error("config error: {0}")]
    Config(String),

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A trap pattern failed to compile as a regex.
    #[error("invalid trap pattern: {0}")]
    Pattern(String),

    /// A network entry was not a valid CIDR.
    #[error("invalid network: {0}")]
    Network(String),
}
