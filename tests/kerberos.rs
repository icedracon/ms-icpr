//! Kerberos sealed-bind wire tests — offline, public-API only.
//!
//! Pin the Kerberos BIND PDU shape so consumers wiring a real AP-REQ (from
//! `picky-krb`, MIT/Heimdal, or an unwrapped ccache) get a deterministic
//! wire layout: the sec_trailer's `auth_type` byte MUST be 0x10
//! (`RPC_C_AUTHN_GSS_KERBEROS`) at the exact offset the CA parses.

use ms_icpr::{
    encode_kerberos_auth3_pdu, encode_kerberos_bind_pdu, KrbTicket, ICPR_SYNTAX_UUID,
    RPC_C_AUTHN_GSS_KERBEROS,
};

/// A byte pattern that mimics a real GSS-KRB5 AP-REQ token prefix (RFC 2743
/// InitialContextToken with the KRB5 mech OID `1.2.840.113554.1.2.2`). The
/// crate treats the token as opaque; the test just wants a plausibly-sized
/// buffer.
fn plausible_ap_req(total_len: usize) -> Vec<u8> {
    let mut v = vec![
        0x60, 0x82, 0x00, 0x00, // APPLICATION[0], DER long-form length
        0x06, 0x09, // OID tag + length
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, // KRB5 OID
        0x01, 0x00, // KRB5 mech-token type: 0x0001 = AP-REQ
    ];
    v.resize(total_len, 0x5A);
    v
}

#[test]
fn kerberos_bind_pdu_auth_type_pinned_to_gss_krb5() {
    let ap_req = plausible_ap_req(200);
    let pdu = encode_kerberos_bind_pdu(1, ICPR_SYNTAX_UUID, 0, 0, &ap_req);

    // The exact location the CA reads: 8 bytes before the auth_value's tail.
    let st = pdu.len() - ap_req.len() - 8;
    assert_eq!(
        pdu[st], RPC_C_AUTHN_GSS_KERBEROS,
        "sec_trailer.auth_type must be 0x10 (GSS_KERBEROS), got 0x{:02x}",
        pdu[st]
    );
    // Never accidentally emit NTLM (0x0a) in the Kerberos path.
    assert_ne!(pdu[st], 0x0a, "must not emit NTLMSSP auth_type");

    // auth_length header field == |AP-REQ|.
    let auth_length = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
    assert_eq!(auth_length, ap_req.len());
    // AP-REQ appears verbatim at the tail.
    assert_eq!(&pdu[pdu.len() - ap_req.len()..], &ap_req[..]);
}

#[test]
fn kerberos_bind_pdu_ptype_is_bind_not_alter_context() {
    // A dumb-but-real regression: someone flips the ptype to 0x0e
    // (ALTER_CONTEXT) mid-refactor and every enroll suddenly fails with
    // BIND_NAK on the CA side. Pin ptype = 0x0b (BIND).
    let ap_req = plausible_ap_req(32);
    let pdu = encode_kerberos_bind_pdu(9, ICPR_SYNTAX_UUID, 0, 0, &ap_req);
    assert_eq!(pdu[2], 0x0b, "ptype must be BIND");
    // First-and-last-frag flags.
    assert_eq!(pdu[3], 0x03);
}

#[test]
fn kerberos_auth3_pdu_shape_for_mutual_auth_ack() {
    // Empty AP-REP-ack (typical KRB5 mutual auth completes in the BIND_ACK
    // and the client just AUTH3s an empty verifier).
    let pdu = encode_kerberos_auth3_pdu(2, &[]);
    assert_eq!(pdu[2], 0x10, "ptype must be AUTH3");
    let st = pdu.len() - 8;
    assert_eq!(pdu[st], RPC_C_AUTHN_GSS_KERBEROS);
    assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), 0);
}

#[test]
fn krb_ticket_debug_never_leaks_session_key() {
    // The session key is derived from user secrets — must never appear in
    // logs. Only the AP-REQ length is loggable.
    let t = KrbTicket::new(vec![0x11; 100], [0xDE; 16]);
    let s = format!("{t:?}");
    assert!(s.contains("ap_req_len: 100"));
    assert!(!s.contains("222, 222"), "raw session-key bytes leaked: {s}");
    assert!(!s.contains("0xde"));
}

#[test]
fn distinct_call_ids_produce_distinct_bind_pdus() {
    // The call_id lives in the header at offset 12..16. Two encodes with
    // different call_ids must differ *only* there — same ap_req, same body.
    let ap_req = plausible_ap_req(48);
    let a = encode_kerberos_bind_pdu(1, ICPR_SYNTAX_UUID, 0, 0, &ap_req);
    let b = encode_kerberos_bind_pdu(2, ICPR_SYNTAX_UUID, 0, 0, &ap_req);
    assert_eq!(a.len(), b.len());
    assert_ne!(a[12..16], b[12..16]);
    // Everything before the call_id AND everything after it must match.
    assert_eq!(a[..12], b[..12]);
    assert_eq!(a[16..], b[16..]);
}
