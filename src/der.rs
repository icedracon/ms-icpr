//! Minimal DER encoder — just enough to build a PKCS#10 CertificationRequest
//! with a SubjectAltName otherName(UPN) extension. Hand-rolled to keep the
//! dep graph flat and the ESC1 primitive fully auditable.
//!
//! Not a general ASN.1 library. Constraints:
//! * Only definite-length forms are emitted.
//! * INTEGER assumes big-endian, prepends 0x00 when needed for positivity.
//! * SET OF is written in encounter order (fine here — we only ever emit one
//!   element per SET).

use crate::error::{Error, Result};

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

/// Constructed context-specific tag `[n]`.
pub const fn ctx_c(n: u8) -> u8 {
    0xA0 | (n & 0x1F)
}

/// Encode a definite-length header for `len` (short form when `<128`, else
/// long form with the minimum number of octets).
pub fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut buf = [0u8; 8];
    let mut n = len;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = (n & 0xff) as u8;
        n >>= 8;
    }
    let bytes = &buf[i..];
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(bytes);
}

/// Wrap `contents` in a `tag`-tagged TLV.
pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 6);
    out.push(tag);
    write_len(&mut out, contents.len());
    out.extend_from_slice(contents);
    out
}

pub fn sequence(contents: &[u8]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, contents)
}
pub fn set(contents: &[u8]) -> Vec<u8> {
    tlv(TAG_SET, contents)
}
pub fn octet_string(contents: &[u8]) -> Vec<u8> {
    tlv(TAG_OCTET_STRING, contents)
}
pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(TAG_UTF8_STRING, s.as_bytes())
}
pub fn null() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}
pub fn boolean(b: bool) -> Vec<u8> {
    vec![TAG_BOOLEAN, 0x01, if b { 0xff } else { 0x00 }]
}

/// INTEGER from a big-endian unsigned magnitude. Trims leading zeros but
/// keeps one 0x00 pad if the MSB is set (to preserve positivity).
pub fn integer_be_unsigned(mag: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < mag.len() && mag[i] == 0 {
        i += 1;
    }
    let trimmed = &mag[i..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(trimmed);
    tlv(TAG_INTEGER, &body)
}

pub fn integer_small(n: i64) -> Vec<u8> {
    // Sufficient for version fields (0..127).
    if !(0..=127).contains(&n) {
        // Only used internally with 0.
        return tlv(TAG_INTEGER, &[0]);
    }
    tlv(TAG_INTEGER, &[n as u8])
}

/// BIT STRING with no unused trailing bits.
pub fn bit_string_no_unused(contents: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(contents.len() + 1);
    body.push(0x00);
    body.extend_from_slice(contents);
    tlv(TAG_BIT_STRING, &body)
}

/// Wrap in `[n] IMPLICIT` (constructed).
pub fn implicit_context(n: u8, contents: &[u8]) -> Vec<u8> {
    tlv(ctx_c(n), contents)
}

/// Wrap in `[n] EXPLICIT` — the inner TLV is re-wrapped in a constructed
/// context tag.
pub fn explicit_context(n: u8, inner_tlv: &[u8]) -> Vec<u8> {
    tlv(ctx_c(n), inner_tlv)
}

/// Encode a dotted OID (e.g. "1.2.840.113549.1.1.11") as a full TLV.
pub fn oid(dotted: &str) -> Result<Vec<u8>> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|p| {
            p.parse::<u64>()
                .map_err(|_| Error::Oid(format!("bad arc `{p}` in {dotted}")))
        })
        .collect::<Result<_>>()?;
    if arcs.len() < 2 {
        return Err(Error::Oid(format!("oid needs >=2 arcs: {dotted}")));
    }
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(Error::Oid(format!("first two arcs out of range: {dotted}")));
    }
    let mut body = Vec::with_capacity(dotted.len());
    body.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        encode_base128(&mut body, arc);
    }
    Ok(tlv(TAG_OID, &body))
}

fn encode_base128(out: &mut Vec<u8>, mut n: u64) {
    // 10 * 7 = 70 bits, enough for u64.
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    // Set continuation bit on all but the last byte.
    let last = buf.len() - 1;
    for b in &mut buf[i..last] {
        *b |= 0x80;
    }
    out.extend_from_slice(&buf[i..]);
}

// ---- tiny reader for the round-trip test in this module -----------------

/// Parses a single TLV, returning `(tag, contents, rest_after_tlv)`.
pub fn parse_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.is_empty() {
        return Err(Error::Invalid("empty TLV".into()));
    }
    let tag = input[0];
    let (len, len_bytes) = parse_len(&input[1..])?;
    let start = 1 + len_bytes;
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::Invalid("length overflow".into()))?;
    if end > input.len() {
        return Err(Error::Invalid("truncated TLV".into()));
    }
    Ok((tag, &input[start..end], &input[end..]))
}

fn parse_len(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        return Err(Error::Invalid("no length octet".into()));
    }
    let first = input[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 8 || 1 + n > input.len() {
        return Err(Error::Invalid("bad long-form length".into()));
    }
    let mut len = 0usize;
    for &b in &input[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_roundtrip_rsa_sha256() {
        // 1.2.840.113549.1.1.11 == sha256WithRSAEncryption
        let der = oid("1.2.840.113549.1.1.11").unwrap();
        assert_eq!(
            der,
            vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
        );
    }

    #[test]
    fn oid_upn() {
        // 1.3.6.1.4.1.311.20.2.3 == userPrincipalName
        let der = oid("1.3.6.1.4.1.311.20.2.3").unwrap();
        assert_eq!(
            der,
            vec![0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03]
        );
    }

    #[test]
    fn len_long_form() {
        let mut out = vec![];
        write_len(&mut out, 300);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn tlv_parse_matches_encode() {
        let s = utf8_string("hi");
        let (tag, contents, rest) = parse_tlv(&s).unwrap();
        assert_eq!(tag, TAG_UTF8_STRING);
        assert_eq!(contents, b"hi");
        assert!(rest.is_empty());
    }
}
