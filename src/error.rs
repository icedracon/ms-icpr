//! Error types for ms-icpr.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid RSA key: {0}")]
    Key(String),

    #[error("signing failed: {0}")]
    Sign(String),

    #[error("invalid oid: {0}")]
    Oid(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    // Reserved for future RPC transport wiring (currently unused because
    // submit_request is stubbed offline — see rpc.rs).
    #[error("rpc transport: {0}")]
    Rpc(String),

    // Live-DC-only surface: returned by submit_request until MS-ICPR / WCCE
    // marshalling is wired to a real \PIPE\cert transport.
    #[error("live-DC-only path not implemented in offline skeleton")]
    LiveDcOnly,
}
