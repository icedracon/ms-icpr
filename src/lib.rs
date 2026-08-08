//! ms-icpr — ICertPassage (MS-ICPR) / WCCE client with an ESC1 CSR-SAN
//! injection primitive.
//!
//! # Purpose
//!
//! Submit certificate requests to an AD-CS Enterprise CA over RPC and retrieve
//! the issued certificate. The offensive path this crate enables is ESC1:
//! against an `enrollee-supplies-subject` template, a low-privileged user
//! ships a CSR with a `SubjectAltName{otherName, userPrincipalName=...}`
//! extension and the CA emits a client-auth certificate bound to any UPN in
//! the domain (e.g. `administrator@corp.local`).
//!
//! # Status: 0.1.0-dev (pre-alpha)
//!
//! - `build_csr_with_upn_san` produces a valid, signed PKCS#10 CSR carrying
//!   the UPN otherName SAN. Offline-testable, round-trip-verified.
//! - `IcprClient::submit_request` performs offline pre-flight checks
//!   (schema version, `min_ra_signatures`, CSR shape) and then returns
//!   [`Error::LiveDcOnly`]. The NDR marshalling of `CertServerRequest`
//!   requires live-DC iteration and is deferred to a follow-up turn.
//! - No SPNEGO/Kerberos wiring; consumers plug in their own transport via
//!   the [`IcprTransport`] trait.
//!
//! # Example
//!
//! ```no_run
//! use ms_icpr::{build_csr_with_upn_san, IcprClient};
//! # let key_pem: &[u8] = b"";
//! # let template: ms_crtd::CertTemplate = unimplemented!();
//! let csr = build_csr_with_upn_san("recon", "administrator@corp.local", key_pem)?;
//! let mut client = IcprClient::stub("corp-CA");
//! // On a live DC this would issue the cert. Offline: Err(LiveDcOnly).
//! let _ = client.submit_request(&template, &csr);
//! # Ok::<(), ms_icpr::Error>(())
//! ```

pub mod csr;
pub mod der;
pub mod error;
pub mod oids;
pub mod rpc;

pub use csr::{build_csr_with_upn_san, parse_rsa_private_key_pem};
pub use error::{Error, Result};
pub use rpc::{IcprClient, IcprTransport, IssuedCert, StubTransport};
