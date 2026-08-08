//! MS-ICPR / MS-WCCE RPC client.
//!
//! Two layers:
//!
//! * A pure NDR encoder/decoder for the `CertServerRequest` opnum (ICertPassage
//!   `91ae6020-9e3c-11cf-8d7c-00aa00c091be` v0.0). Byte layout is
//!   impacket-equivalent — every pointee inlined right after its referent, in
//!   field order — and testable offline. This is what a caller with an
//!   external transport (a relayed DCE/RPC session, a fuzzer harness) plugs
//!   into via [`IcprTransport`].
//! * A sealed `\PIPE\cert` transport ([`NetworkTransport`], behind the
//!   default `network` cargo feature). This does SMB2 → IPC$ → open `cert`
//!   pipe → NTLMSSP sealed bind → `CertServerRequest` opnum 0 call. When the
//!   feature is off, only the encoder/decoder + [`StubTransport`] are built.
//!
//! # Example (offline)
//!
//! ```
//! use ms_icpr::rpc::{encode_cert_server_request, decode_cert_server_response};
//! let bytes = encode_cert_server_request("corp-CA-01", "User", &[0x30, 0x03, 0x02, 0x01, 0x00]);
//! assert!(!bytes.is_empty());
//! // A live DC would return an NDR blob decodable via `decode_cert_server_response`.
//! let _ = decode_cert_server_response(&bytes); // will error on this arbitrary buffer
//! ```

use crate::error::{Error, Result};
use ms_crtd::CertTemplate;
use ms_ndr::{NdrDecoder, NdrEncoder, NdrError};

/// ICertPassage `CertServerRequest` opnum on `\PIPE\cert`.
///
/// MS-ICPR §3.2.4.1: the interface exposes a single method at opnum 0.
pub const CERT_SERVER_REQUEST_OPNUM: u16 = 0;

/// Trait for a DCE/RPC transport carrying the ICertPassage
/// (`91ae6020-9e3c-11cf-8d7c-00aa00c091be` v0.0) interface. Given an already
/// NDR-marshaled `CertServerRequest` input stub, returns the raw NDR response
/// stub.
pub trait IcprTransport {
    fn cert_server_request(&mut self, marshaled_in: &[u8]) -> Result<Vec<u8>>;
}

/// Placeholder transport used for offline unit tests / doc examples. Every
/// call returns [`Error::LiveDcOnly`].
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
    /// CA-assigned request id (`RequestId` column in `certutil`).
    pub request_id: u32,
    /// CA disposition (`3 = ISSUED`; anything else is a rejection reason).
    pub disposition: u32,
    /// Human-readable disposition message from the CA.
    pub message: String,
}

/// MS-ICPR client.
///
/// Construct with any [`IcprTransport`], or use [`IcprClient::stub`] for
/// offline tests. The default `network` feature adds
/// [`IcprClient::connect`] which returns a client pre-wired to a sealed
/// `\PIPE\cert` transport.
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

    /// Return the exact NDR-marshaled `CertServerRequest` input stub that
    /// [`submit_request`](Self::submit_request) will hand to the transport.
    /// Runs all offline preflight (see the crate docs) but no I/O — useful
    /// for byte-layout tests, replay fixtures, or fuzz harnesses.
    pub fn marshal_call(&self, template: &CertTemplate, csr_der: &[u8]) -> Result<Vec<u8>> {
        preflight(template, csr_der)?;
        Ok(encode_cert_server_request(
            &self.ca_name,
            &template.name,
            csr_der,
        ))
    }

    /// Submit `csr_der` against `template`. On a live DC this returns the
    /// issued certificate. With [`StubTransport`] it returns
    /// [`Error::LiveDcOnly`] after successful preflight.
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
        let stub = self.marshal_call(template, csr_der)?;
        let resp = self.transport.cert_server_request(&stub)?;
        let cs = decode_cert_server_response(&resp)?;
        if cs.disposition != 3 {
            return Err(Error::Rpc(format!(
                "CA disposition {} — {}",
                cs.disposition, cs.message
            )));
        }
        if cs.cert_der.is_empty() {
            return Err(Error::Rpc(
                "CA disposition ISSUED but pctbEncodedCert is empty".into(),
            ));
        }
        Ok(IssuedCert {
            pem: der_to_pem_certificate(&cs.cert_der),
            request_id: cs.request_id,
            disposition: cs.disposition,
            message: cs.message,
        })
    }
}

impl IcprClient<StubTransport> {
    /// Convenience constructor for tests and doc examples.
    pub fn stub(ca_name: impl Into<String>) -> Self {
        IcprClient::new(StubTransport, ca_name)
    }
}

fn preflight(template: &CertTemplate, csr_der: &[u8]) -> Result<()> {
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
    Ok(())
}

// ─── wire encoder / decoder ─────────────────────────────────────────────────

/// UTF-16LE bytes of `s` with a trailing NUL — the CERTTRANSBLOB string form
/// used for `pctbAttribs`.
fn utf16z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

/// Marshal `CertServerRequest` `[in]` params, matching impacket's
/// `CertServerRequest.getData()` byte-for-byte:
///
/// ```text
///   dwFlags:            u32 (0)
///   pwszAuthority:      referent + inline conformant-varying WSTR
///   pdwRequestId:       u32 (in-value, 0)
///   pctbAttribs:        u32 cb + referent + inline u32 max_count + bytes + pad
///   pctbRequest:        u32 cb + referent + inline u32 max_count + bytes + pad
/// ```
///
/// The `pctbAttribs` payload we build is
/// `UTF-16LE("CertificateTemplate:<template>") + NUL`. Multi-attribute blobs
/// (e.g. `CertificateTemplate:X\nSAN:...`) are `\n`-separated within the same
/// UTF-16LE buffer; ESC1 needs only the template name.
pub fn encode_cert_server_request(authority: &str, template: &str, csr_der: &[u8]) -> Vec<u8> {
    let attribs = utf16z(&format!("CertificateTemplate:{template}"));
    let mut e = NdrEncoder::new();
    e.u32(0); // dwFlags
    e.referent(); // pwszAuthority referent
    e.conformant_varying_wstr(authority); // inline LPWSTR pointee
    e.align(4);
    e.u32(0); // pdwRequestId (DWORD in-value)
              // pctbAttribs CERTTRANSBLOB.
    e.u32(attribs.len() as u32);
    e.referent();
    e.u32(attribs.len() as u32); // array max_count
    e.bytes(&attribs);
    e.align(4);
    // pctbRequest CERTTRANSBLOB.
    e.u32(csr_der.len() as u32);
    e.referent();
    e.u32(csr_der.len() as u32);
    e.bytes(csr_der);
    e.align(4);
    e.into_bytes()
}

/// Decoded `CertServerRequest` `[out]` reply.
#[derive(Debug, Clone)]
pub struct CertServerResponse {
    pub request_id: u32,
    pub disposition: u32,
    pub cert_chain: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub message: String,
}

/// Decode the `CertServerRequest` reply stub.
///
/// Layout (MS-WCCE §3.2.2.6.2.1.4):
///
/// ```text
///   pdwRequestId:            u32
///   pdwDisposition:          u32
///   pctbCertChain:           CERTTRANSBLOB (PKCS#7)
///   pctbEncodedCert:         CERTTRANSBLOB (DER X.509)
///   pctbDispositionMessage:  CERTTRANSBLOB (UTF-16LE)
/// ```
pub fn decode_cert_server_response(stub: &[u8]) -> Result<CertServerResponse> {
    let mut d = NdrDecoder::new(stub);
    let request_id = d.u32().map_err(ndr_err)?;
    let disposition = d.u32().map_err(ndr_err)?;
    let cert_chain = read_blob(&mut d)?;
    let cert_der = read_blob(&mut d)?;
    let msg_raw = read_blob(&mut d)?;
    let message = String::from_utf16_lossy(
        &msg_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('\0')
    .to_string();
    Ok(CertServerResponse {
        request_id,
        disposition,
        cert_chain,
        cert_der,
        message,
    })
}

/// Read one out-CERTTRANSBLOB: `cb`, `pb` referent, and (inline) the
/// conformant byte array.
fn read_blob(d: &mut NdrDecoder) -> Result<Vec<u8>> {
    let cb = d.u32().map_err(ndr_err)? as usize;
    let ptr = d.u32().map_err(ndr_err)?;
    if ptr == 0 || cb == 0 {
        return Ok(Vec::new());
    }
    let _max = d.u32().map_err(ndr_err)?;
    let v = d.read_bytes(cb).map_err(ndr_err)?.to_vec();
    d.align(4);
    Ok(v)
}

fn ndr_err(e: NdrError) -> Error {
    Error::Rpc(format!("ndr: {e}"))
}

/// DER → PEM CERTIFICATE, 64-char base64 lines. Hand-rolled base64 to avoid a
/// dep — the CA replies with certificates in the ~1-2 KB range, so an
/// allocating encoder is fine.
fn der_to_pem_certificate(der: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let (b0, b1, b2, pad) = match chunk.len() {
            3 => (chunk[0], chunk[1], chunk[2], 0),
            2 => (chunk[0], chunk[1], 0, 1),
            1 => (chunk[0], 0, 0, 2),
            _ => unreachable!(),
        };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        b64.push(ALPHABET[((n >> 18) & 0x3f) as usize]);
        b64.push(ALPHABET[((n >> 12) & 0x3f) as usize]);
        b64.push(if pad >= 2 {
            b'='
        } else {
            ALPHABET[((n >> 6) & 0x3f) as usize]
        });
        b64.push(if pad >= 1 {
            b'='
        } else {
            ALPHABET[(n & 0x3f) as usize]
        });
    }
    let mut pem = Vec::with_capacity(b64.len() + 64);
    pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    for line in b64.chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    pem
}

// ─── live \PIPE\cert transport (feature = "network") ────────────────────────

#[cfg(feature = "network")]
pub use network::NetworkTransport;

#[cfg(feature = "network")]
mod network {
    use super::*;
    use dcerpc::transport::SmbPipe;
    use dcerpc::Syntax;

    fn icpr_syntax() -> Syntax {
        // MS-ICPR ICertPassage interface (v0.0).
        Syntax::new("91ae6020-9e3c-11cf-8d7c-00aa00c091be", 0, 0)
    }

    /// Sealed `\PIPE\cert` transport. `connect()` performs SMB2 negotiate +
    /// NTLM session setup + `IPC$` tree connect. Each
    /// [`IcprTransport::cert_server_request`] call opens the `cert` pipe,
    /// binds ICPR with NTLMSSP sign+seal (RPC packet privacy — required, the
    /// CA rejects plaintext), and dispatches `CertServerRequest` opnum 0.
    pub struct NetworkTransport {
        client: smb2_client::SmbClient,
        host: String,
        domain: String,
        user: String,
        password: String,
        runtime: tokio::runtime::Runtime,
    }

    impl NetworkTransport {
        /// Log in to `host` (a DNS name or IP reachable over SMB2/445) with
        /// plaintext creds and tree-connect to `\\host\IPC$`.
        pub fn connect(host: &str, domain: &str, user: &str, password: &str) -> Result<Self> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| Error::Rpc(format!("tokio runtime: {e}")))?;
            let host_owned = host.to_string();
            let domain_owned = domain.to_string();
            let user_owned = user.to_string();
            let password_owned = password.to_string();
            let client = runtime.block_on(async {
                let mut c = smb2_client::SmbClient::connect(&host_owned)
                    .await
                    .map_err(|e| Error::Rpc(format!("smb connect {host_owned}: {e}")))?;
                c.login(&host_owned, &domain_owned, &user_owned, &password_owned)
                    .await
                    .map_err(|e| Error::Rpc(format!("smb login: {e}")))?;
                c.tree_connect(&format!("\\\\{host_owned}\\IPC$"))
                    .await
                    .map_err(|e| Error::Rpc(format!("tree_connect IPC$: {e}")))?;
                Ok::<_, Error>(c)
            })?;
            Ok(NetworkTransport {
                client,
                host: host.into(),
                domain: domain.into(),
                user: user.into(),
                password: password.into(),
                runtime,
            })
        }
    }

    impl IcprTransport for NetworkTransport {
        fn cert_server_request(&mut self, marshaled_in: &[u8]) -> Result<Vec<u8>> {
            let Self {
                client,
                host,
                domain,
                user,
                password,
                runtime,
            } = self;
            let stub = marshaled_in.to_vec();
            runtime.block_on(async move {
                let file_id = client
                    .open_pipe("cert")
                    .await
                    .map_err(|e| Error::Rpc(format!("open pipe \\cert: {e}")))?;
                let mut pipe = SmbPipe::new(client, file_id);
                pipe.bind_sealed(icpr_syntax(), domain, user, password, host)
                    .await
                    .map_err(|e| Error::Rpc(format!("bind_sealed icpr: {e}")))?;
                let resp = pipe
                    .call_sealed(CERT_SERVER_REQUEST_OPNUM, &stub)
                    .await
                    .map_err(|e| Error::Rpc(format!("call_sealed CertServerRequest: {e}")))?;
                Ok::<_, Error>(resp)
            })
        }
    }

    impl super::IcprClient<NetworkTransport> {
        /// One-shot: SMB2 login + IPC$ tree-connect, wrap in an
        /// [`IcprClient`] targeting the CA named `ca_name`. Subsequent
        /// [`submit_request`](super::IcprClient::submit_request) calls open
        /// the sealed `\PIPE\cert`, bind, and dispatch.
        pub fn connect(
            host: &str,
            domain: &str,
            user: &str,
            password: &str,
            ca_name: impl Into<String>,
        ) -> Result<Self> {
            let transport = NetworkTransport::connect(host, domain, user, password)?;
            Ok(super::IcprClient::new(transport, ca_name))
        }
    }
}

// Re-export the CSR builder so `IcprClient::submit_request` and
// `build_csr_with_upn_san` sit side-by-side in the public API.
pub use crate::csr::build_csr_with_upn_san;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16z_has_terminator() {
        assert_eq!(utf16z("A"), vec![0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn wire_encode_matches_impacket_layout() {
        // Same input as the dcerpc crate's live-validated fixture: 10-char
        // authority ("corp-CA-01"), template "VulnUser", 20 bytes of CSR.
        // impacket-equivalent length = 152 bytes.
        let s =
            encode_cert_server_request("corp-CA-01", "VulnUser", &(0..20u8).collect::<Vec<u8>>());
        assert_eq!(s.len(), 152, "stub length must match impacket");
        assert_eq!(u32::from_le_bytes(s[0..4].try_into().unwrap()), 0); // dwFlags
        assert_ne!(u32::from_le_bytes(s[4..8].try_into().unwrap()), 0); // authority referent
        assert_eq!(u32::from_le_bytes(s[8..12].try_into().unwrap()), 11); // authority max_count
                                                                          // pctbAttribs.cb sits at offset 48: "CertificateTemplate:VulnUser" =
                                                                          // 28 chars * 2 (UTF-16LE) + 2 (NUL) = 58 bytes.
        assert_eq!(u32::from_le_bytes(s[48..52].try_into().unwrap()), 58);
    }

    #[test]
    fn decode_roundtrips_a_synthetic_response() {
        // Synthesize a plausible response: request_id=42, disposition=3,
        // empty chain, "hello" as fake DER cert, "OK" as UTF-16LE message.
        let mut e = NdrEncoder::new();
        e.u32(42); // request_id
        e.u32(3); // ISSUED
                  // empty chain: cb=0, null ptr
        e.u32(0);
        e.u32(0);
        // cert blob: cb=5, referent, max_count=5, "hello", pad to 4
        e.u32(5);
        e.referent();
        e.u32(5);
        e.bytes(b"hello");
        e.align(4);
        // message blob: "OK\0" as UTF-16LE = 6 bytes
        let msg = utf16z("OK");
        e.u32(msg.len() as u32);
        e.referent();
        e.u32(msg.len() as u32);
        e.bytes(&msg);
        e.align(4);
        let bytes = e.into_bytes();

        let cs = decode_cert_server_response(&bytes).expect("decode");
        assert_eq!(cs.request_id, 42);
        assert_eq!(cs.disposition, 3);
        assert!(cs.cert_chain.is_empty());
        assert_eq!(cs.cert_der, b"hello");
        assert_eq!(cs.message, "OK");
    }

    #[test]
    fn der_to_pem_is_wellformed() {
        let der = b"hello";
        let pem = der_to_pem_certificate(der);
        let s = std::str::from_utf8(&pem).unwrap();
        assert!(s.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(s.ends_with("-----END CERTIFICATE-----\n"));
        assert!(s.contains("aGVsbG8=")); // base64("hello")
    }
}
