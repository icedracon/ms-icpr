# ms-icpr

[![Crates.io](https://img.shields.io/crates/v/ms-icpr.svg)](https://crates.io/crates/ms-icpr)
[![Docs.rs](https://docs.rs/ms-icpr/badge.svg)](https://docs.rs/ms-icpr)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

MS-ICPR (`ICertPassage`) / MS-WCCE client for AD CS enrollment, in Rust — with a first-class **ESC1** primitive: build a PKCS#10 CSR that carries a `SubjectAltName{otherName, userPrincipalName}` bound to an arbitrary UPN.

## Status

**`0.1.0-dev`** — pre-alpha, offline skeleton. Network transport wiring is stubbed pending a live-DC iteration. API is unstable; expect breaks before `0.1.0`. Part of the [icedracon Rust offensive AD ecosystem](https://github.com/icedracon).

## What it does

Submits certificate requests to an Enterprise CA over MS-WCCE / MS-ICPR RPC and, once the network layer is wired, retrieves the issued cert. The offensive path exercised here is **ESC1**: against a template that sets `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + a client-auth EKU, a low-privileged user requests a certificate carrying `UPN=administrator@corp.local` and then Kerberos-authenticates as that user via PKINIT.

Consumes [`ms-crtd`](https://github.com/icedracon/ms-crtd)`::CertTemplate` for offline pre-flight, so submitting against an obviously-non-abusable template fails locally before any RPC round-trip.

## Usage

```rust
use ms_icpr::{build_csr_with_upn_san, IcprClient};

// The ESC1 primitive: subject CN + UPN otherName in one CSR
let csr = build_csr_with_upn_san(
    "recon",
    "administrator@corp.local",
    &std::fs::read("./key.pem")?,
)?;

// Offline pre-flight (schema >= 1, no RA sigs, DER-well-formed);
// StubTransport returns Error::LiveDcOnly today.
let mut client = IcprClient::stub("corp-CA");
match client.submit_request(&template, &csr) {
    Ok(cert) => std::fs::write("./issued.pem", &cert.pem)?,
    Err(e)   => eprintln!("submit failed (expected offline): {e}"),
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What works / what does not (this version)

- Working:
  - `build_csr_with_upn_san(subject, upn, key_pem) -> Vec<u8>` — valid PKCS#10 CSR, SHA256-RSA signed, carrying `SubjectAltName{otherName(UPN)}`. Deterministic, offline, round-trip-tested with `x509-cert`.
  - `parse_rsa_private_key_pem` — accepts both PKCS#8 and PKCS#1 PEM.
  - `IcprClient::submit_request` — offline pre-flight (`schema_version >= 1`, `min_ra_signatures <= 0`, CSR is DER SEQUENCE) then dispatches through an `IcprTransport` trait — bring your own for testing.
- Stubbed / deferred:
  - NDR marshalling of `CertServerRequest` `[in]`/`[out]` parameters — needs live-DC iteration for pointee ordering
  - SMB `\PIPE\cert` and DCOM `ncacn_ip_tcp` sealed-bind wiring
  - Certificate-response parsing (CERTTRANSBLOB -> PEM)
  - Only single-RDN subjects (`CN=<subject>`), only RSA keys, exactly one otherName per SAN — mechanical extensions

## Related icedracon crates

Part of a 4-crate ADCS attack chain — template parsing all the way to a live PKINIT-derived TGT:

- [`ms-crtd`](https://github.com/icedracon/ms-crtd) — parse `pKICertificateTemplate` LDAP attrs, emit ESC findings
- **ms-icpr** (this crate) — submit ESC1 CSRs to the CA over MS-ICPR / MS-WCCE
- [`ms-pkca`](https://github.com/icedracon/ms-pkca) — PKINIT the issued cert into a Kerberos TGT + UnPAC-the-hash
- [`ms-kile-fast`](https://github.com/icedracon/ms-kile-fast) — RFC 6113 FAST armor for the AS-REQ / TGS-REQ

Together they aim for [Certipy](https://github.com/ly4k/Certipy) parity in pure Rust with an S-tier dep tree.

## Dependencies

Deliberately narrow: `rsa`, `sha2`, `x509-cert` (structural round-trip only), `thiserror`, plus the workspace crates `dcerpc`, `ms-ndr`, `ms-crtd`. Zero `serde_json`, zero macro-heavy frameworks. The DER encoder is hand-rolled (~200 LOC) — same posture as `hashglass`.

The `network` feature (on by default) pulls `dcerpc`, `smb2-client`, and `tokio`. Disable for pure offline builds that only need the CSR builder and wire-format encoder.

## License

MIT (C) 2026 [zevs](https://github.com/icedracon)
