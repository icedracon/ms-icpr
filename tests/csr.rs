//! CSR builder integration tests.
//!
//! These build a fresh 1024-bit RSA key at test time (cheap enough for CI —
//! ~200-500ms) so we don't need to ship a hardcoded private key just for a
//! shape check.

use ms_icpr::der;
use ms_icpr::{build_csr_with_upn_san, oids};

use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;

fn fresh_key_pem() -> Vec<u8> {
    let key = RsaPrivateKey::new(&mut OsRng, 1024).expect("keygen");
    key.to_pkcs8_pem(LineEnding::LF)
        .expect("pem")
        .as_bytes()
        .to_vec()
}

fn upn_oid_bytes() -> Vec<u8> {
    // TLV of 1.3.6.1.4.1.311.20.2.3
    der::oid(oids::MS_USER_PRINCIPAL_NAME).unwrap()
}

#[test]
fn csr_contains_upn_san_bytes() {
    let key = fresh_key_pem();
    let csr = build_csr_with_upn_san("recon", "administrator@corp.local", &key).unwrap();

    // Outer envelope is an ASN.1 SEQUENCE.
    assert_eq!(csr[0], 0x30, "csr should start with SEQUENCE tag");

    // The UPN OID TLV must appear (in the SAN otherName type-id slot).
    let needle = upn_oid_bytes();
    assert!(
        csr.windows(needle.len()).any(|w| w == needle),
        "csr should contain UPN OID DER"
    );

    // The UPN string itself must appear as a UTF8String tag+len+bytes.
    let upn = b"administrator@corp.local";
    let mut with_tag = vec![0x0c, upn.len() as u8];
    with_tag.extend_from_slice(upn);
    assert!(
        csr.windows(with_tag.len()).any(|w| w == with_tag),
        "csr should contain UTF8String(UPN)"
    );
}

#[test]
fn csr_signature_algorithm_is_sha256_with_rsa() {
    let key = fresh_key_pem();
    let csr = build_csr_with_upn_san("recon", "administrator@corp.local", &key).unwrap();

    // CertificationRequest ::= SEQUENCE { cri, sigAlgo, sigBits }
    let (tag, outer, rest) = der::parse_tlv(&csr).unwrap();
    assert_eq!(tag, der::TAG_SEQUENCE);
    assert!(rest.is_empty(), "trailing bytes after CSR");

    let (_, _cri, rest) = der::parse_tlv(outer).unwrap();
    let (tag, sig_algo_body, rest) = der::parse_tlv(rest).unwrap();
    assert_eq!(tag, der::TAG_SEQUENCE, "sigAlgo must be SEQUENCE");

    let (tag, algo_oid, _) = der::parse_tlv(sig_algo_body).unwrap();
    assert_eq!(tag, der::TAG_OID);

    let expected = der::oid(oids::SHA256_WITH_RSA).unwrap();
    // `expected` is the full TLV; strip its 2-byte header for comparison.
    assert_eq!(algo_oid, &expected[2..]);

    // Signature bit string comes next.
    let (tag, sig_body, tail) = der::parse_tlv(rest).unwrap();
    assert_eq!(tag, der::TAG_BIT_STRING);
    assert!(tail.is_empty(), "trailing bytes after signature");
    assert_eq!(sig_body[0], 0x00, "expected 0 unused bits");
    // 1024-bit RSA signature = 128 bytes; +1 for the unused-bits octet.
    assert_eq!(sig_body.len(), 128 + 1);
}

#[test]
fn csr_rejects_upn_without_at_sign() {
    let key = fresh_key_pem();
    let err =
        build_csr_with_upn_san("recon", "no-at-sign", &key).expect_err("bare string is not a UPN");
    let msg = format!("{err}");
    assert!(msg.contains("upn"), "want upn-shape error, got {msg}");
}
