//! MS-ICPR / MS-WCCE RPC client scaffold.
//!
//! STATUS: transport is a placeholder. The real client needs a sealed RPC
//! bind to the `\PIPE\cert` endpoint (or `ncacn_ip_tcp` DCOM for WCCE) and
//! must marshal `CertServerRequest` with NDR. Live-DC iteration is required
//! to shake down the NDR pointee ordering — see the notes in
//! `dcerpc::icpr` in the workspace (READ-ONLY reference).
//!
//! Until then, `IcprClient::submit_request` returns `Error::LiveDcOnly` so
//! callers get a real, honest failure instead of a `todo!()` panic.

use crate::csr;
use crate::error::{Error, Result};
use ms_crtd::CertTemplate;

/// Trait for a DCERPC transport capable of carrying the ICertPassage
/// interface (`91ae6020-9e3c-11cf-8d7c-00aa00c091be` v0.0). The workspace
/// crate `dcerpc` provides an SMB `\PIPE\cert` implementation; this
/// abstraction is here so tests can swap in an in-memory replayer later.
pub trait IcprTransport {
    /// Call `CertServerRequest` (opnum 0) with an already-marshaled request
    /// blob and return the raw response bytes.
    fn cert_server_request(&mut self, marshaled_in: &[u8]) -> Result<Vec<u8>>;
}

/// Placeholder transport used when constructing an `IcprClient` for offline
/// unit tests. Every call returns `Error::LiveDcOnly`.
pub struct StubTransport;

impl IcprTransport for StubTransport {
    fn cert_server_request(&mut self, _marshaled_in: &[u8]) -> Result<Vec<u8>> {
        Err(Error::LiveDcOnly)
    }
}

/// An issued certificate returned by the CA.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// PEM-encoded X.509 certificate.
    pub pem: Vec<u8>,
    /// CA-assigned request id (the `RequestId` column in `certutil`).
    pub request_id: u32,
}

/// MS-ICPR client.
///
/// Construct with a transport implementing `IcprTransport`. The
/// higher-level `submit_request` composes the CA-name attribute, the
/// `CertificateTemplate:<template>` request attribute, and the CSR into
/// the CERTTRANSBLOB parameters — but the actual marshaling is stubbed
/// until we integrate with a live DC (see module doc).
pub struct IcprClient<T: IcprTransport> {
    transport: T,
    ca_name: String,
}

impl<T: IcprTransport> IcprClient<T> {
    pub fn new(transport: T, ca_name: impl Into<String>) -> Self {
        Self {
            transport,
            ca_name: ca_name.into(),
        }
    }

    pub fn ca_name(&self) -> &str {
        &self.ca_name
    }

    /// Submit `csr_der` against `template`. On a live DC this returns the
    /// issued certificate; in the offline skeleton it returns
    /// `Error::LiveDcOnly` after doing every offline-safe check we can.
    ///
    /// Offline pre-flight enforced here:
    /// * CSR is non-empty and starts with an ASN.1 SEQUENCE tag (0x30).
    /// * Template shape is at least schema v1.
    /// * Template's `min_ra_signatures` is `<= 0` — otherwise an ESC1-style
    ///   submission will be silently blocked by the CA (enrollment agent
    ///   must co-sign) and we save the caller a round-trip.
    pub fn submit_request(
        &mut self,
        template: &CertTemplate,
        csr_der: &[u8],
    ) -> Result<IssuedCert> {
        if csr_der.is_empty() || csr_der[0] != 0x30 {
            return Err(Error::Invalid("csr_der is not an ASN.1 SEQUENCE".into()));
        }
        if template.schema_version < 1 {
            return Err(Error::Invalid(format!(
                "template `{}` has bad schema version {}",
                template.name, template.schema_version
            )));
        }
        if template.min_ra_signatures > 0 {
            return Err(Error::Invalid(format!(
                "template `{}` requires {} RA signature(s) — ESC1-shape submit will be rejected",
                template.name, template.min_ra_signatures
            )));
        }

        // Build the request-attributes string as WCCE expects it:
        //   "CertificateTemplate:<templateName>\n"
        // (extra attributes could go here; the CA parses `key:value` pairs
        // separated by \n or NUL). Constructed but currently unused because
        // marshalling is stubbed; kept so submit_request does the work
        // that's testable offline.
        let _attributes = format!("CertificateTemplate:{}\n", template.name);

        // TODO(live-DC): marshal CertServerRequest [in] params (dwFlags,
        // pwszAuthority=self.ca_name, pdwRequestId=0, pctbAttribs, pctbRequest)
        // via ms-ndr and dispatch through `self.transport.cert_server_request`.
        // Then parse [out] pdwRequestId, pdwDisposition, pctbCert,
        // pctbEncodedCert, pctbDispositionMessage. See `dcerpc::icpr` in the
        // workspace for the LIVE-VALIDATED byte layout.
        let _ = self.transport.cert_server_request(&[])?;

        // Unreachable in the skeleton (transport always errors) — kept so
        // the return type is real, not `!`.
        Ok(IssuedCert {
            pem: Vec::new(),
            request_id: 0,
        })
    }
}

impl IcprClient<StubTransport> {
    /// Convenience constructor for tests and doc examples.
    pub fn stub(ca_name: impl Into<String>) -> Self {
        IcprClient::new(StubTransport, ca_name)
    }
}

// Re-export the CSR builder at the crate top so `IcprClient::submit_request`
// and `build_csr_with_upn_san` sit side-by-side in the public API.
pub use csr::build_csr_with_upn_san;
