# ms-icpr

**STATUS: 0.1.0-dev — pre-alpha, offline skeleton.**

MS-ICPR / MS-WCCE client for AD-CS enrollment, with an ESC1 CSR
`SubjectAltName{otherName, userPrincipalName}` injection primitive.

## Purpose

Submit certificate requests to an Enterprise CA over RPC and retrieve the
issued cert. The offensive path exercised here is **ESC1**: against an
`ENROLLEE_SUPPLIES_SUBJECT` template, a low-privileged user can request a
client-auth certificate bound to any UPN in the domain (e.g.
`administrator@corp.local`) and then Kerberos-authenticate as that user via
PKINIT.

Consumes `ms-crtd::CertTemplate` for template-shape pre-flight so submitting
against an obviously-non-abusable template fails locally.

## What works today

- `build_csr_with_upn_san(subject, upn, key_pem) -> Vec<u8>` — produces a
  valid PKCS#10 CSR signed with SHA256-RSA, carrying a SubjectAltName
  otherName(UPN) extension. Deterministic, offline, round-trip-testable.
- `parse_rsa_private_key_pem` — accepts both PKCS#8 and PKCS#1 PEM.
- `IcprClient::submit_request` — offline pre-flight checks
  (`schema_version >= 1`, `min_ra_signatures <= 0`, CSR is DER SEQUENCE)
  then dispatches through an `IcprTransport`. The bundled `StubTransport`
  returns `Error::LiveDcOnly`.

## What is stubbed

- NDR marshalling of `CertServerRequest` [in]/[out] parameters —
  needs live-DC iteration for pointee ordering. See `dcerpc::icpr` in the
  workspace (READ-ONLY reference).
- SMB `\PIPE\cert` / DCOM `ncacn_ip_tcp` sealed-bind wiring.
- Certificate-response parsing (CERTTRANSBLOB → PEM).

## Minimal usage

```rust
use ms_icpr::{build_csr_with_upn_san, IcprClient};

let csr = build_csr_with_upn_san(
    "recon",
    "administrator@corp.local",
    &std::fs::read("./key.pem")?,
)?;

let mut client = IcprClient::stub("corp-CA");
match client.submit_request(&template, &csr) {
    Ok(cert) => std::fs::write("./issued.pem", &cert.pem)?,
    Err(e) => eprintln!("submit failed (expected offline): {e}"),
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Layout

```
src/
  lib.rs      # public re-exports
  der.rs      # hand-rolled minimal DER encoder + tiny reader
  oids.rs     # well-known OIDs
  csr.rs      # PKCS#10 builder — the ESC1 primitive
  rpc.rs      # IcprClient + IcprTransport trait + StubTransport
  error.rs    # thiserror Error enum

tests/
  csr.rs      # CSR shape + signature-algo + input-validation
  rpc.rs      # pre-flight + stub-transport LiveDcOnly path
```

## Known gaps

- Only single-RDN subjects (`CN=<subject>`) are emitted.
- Only RSA keys. ECDSA support means adding a second signing branch and
  emitting `SubjectPublicKeyInfo` for `id-ecPublicKey`.
- `subject_alt_name_upn_ext` emits exactly one otherName. Multi-SAN
  requires a `Vec<GeneralName>` builder.
- No DER re-parser check inside `build_csr_with_upn_san` — callers who
  want strict validation can round-trip through `x509-cert`.

## Dependencies

Deliberately narrow: `rsa`, `sha2`, `x509-cert` (structural round-trip
only), `thiserror`, plus the workspace crates `dcerpc`, `ms-ndr`, `ms-crtd`.
Zero `serde_json`, zero macro-heavy frameworks. The DER encoder is
hand-rolled (~200 LOC) — same posture as `hashglass`.

## License

MIT.
