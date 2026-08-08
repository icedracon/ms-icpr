//! MS-ICPR Kerberos sealed-bind wire encoder.
//!
//! Adds the Kerberos (GSS-KRB5, `RPC_C_AUTHN_GSS_KERBEROS = 0x10`) auth path to
//! the ICertPassage BIND PDU. Purpose: enroll certificates under a Kerberos
//! service ticket (SPN typically `HOST/ca-server-fqdn`) so the request rides
//! `AS-REQ`/`TGS-REQ` traffic that many blue teams look at less than NTLMSSP
//! sealed pipes.
//!
//! Scope of this module (0.1.0-dev):
//!
//! * Wire-format encoder for the `BIND` PDU carrying a Kerberos auth verifier
//!   ([`encode_kerberos_bind_pdu`]).
//! * Wire-format encoder for the follow-up `AUTH3` carrying the mutual-auth
//!   `AP-REP` reply (or an empty verifier when mutual auth is off,
//!   [`encode_kerberos_auth3_pdu`]).
//! * A [`KrbTicket`] carrier for the opaque `AP-REQ` GSS token + 16-byte
//!   subkey the caller obtained from a KDC / `MIT`, `Heimdal`, `picky-krb`,
//!   or by unwrapping a `ccache`.
//!
//! Not in scope: the RFC 4121 GSS-KRB5 per-message wrap that a real
//! `CertServerRequest` call needs — the sealed request/response codepath still
//! lives on top of NTLMSSP (`ntlmssp::SealState` via `dcerpc`). The BIND wire
//! is complete and pinned by tests; the sealing layer is the next milestone.
//!
//! # Example (offline)
//!
//! ```
//! use ms_icpr::kerberos::{encode_kerberos_bind_pdu, ICPR_SYNTAX_UUID,
//!     RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_LEVEL_PKT_PRIVACY};
//! // opaque GSS-KRB5 AP-REQ token (would come from a KDC round-trip).
//! let ap_req = vec![0x60, 0x82, 0x04, 0x00, 0x06, 0x09, 0x2a, 0x86, 0x48];
//! let pdu = encode_kerberos_bind_pdu(1, ICPR_SYNTAX_UUID, 0, 0, &ap_req);
//! // sec_trailer.auth_type sits 8 bytes before the token.
//! let st = pdu.len() - ap_req.len() - 8;
//! assert_eq!(pdu[st], RPC_C_AUTHN_GSS_KERBEROS);
//! assert_eq!(pdu[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
//! ```

/// DCE/RPC authentication service: Kerberos v5 (GSS-KRB5), per MS-RPCE
/// §2.2.2.11 and IANA registry. `0x10` in the sec_trailer's `auth_type` byte
/// tells the server the `auth_value` is a GSS-KRB5 token (AP-REQ on BIND,
/// AP-REP on the BIND_ACK, per-message tokens on subsequent PDUs).
pub const RPC_C_AUTHN_GSS_KERBEROS: u8 = 0x10;

/// Sign+seal (PKT privacy) — the only auth level the CA accepts on
/// `\PIPE\cert`.
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u8 = 0x06;

/// ICertPassage interface UUID (MS-ICPR §1.9, v0.0), as raw DCE-encoded
/// bytes. Handy for callers building their own BIND wire.
pub const ICPR_SYNTAX_UUID: [u8; 16] = [
    0x20, 0x60, 0xae, 0x91, 0x3c, 0x9e, 0xcf, 0x11, 0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe,
];

/// NDR transfer syntax v2.0 UUID, offered by every BIND (DCE 1.1 §14.5).
pub const NDR_TRANSFER_SYNTAX_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

/// A Kerberos service ticket usable to authenticate the ICPR BIND.
///
/// `ap_req` is the GSS-wrapped `AP-REQ` token the caller obtained from a KDC
/// for the ICPR service (SPN typically `HOST/ca-server-fqdn`). `session_key`
/// is the 16-byte AP-REQ authenticator subkey (used by an RFC 4121 sealer to
/// wrap subsequent PDUs; wiring that sealer is future work).
///
/// This crate does not talk to a KDC — build the ticket with whatever
/// Kerberos toolkit is on hand (`picky-krb`, MIT/Heimdal `gss_init_sec_context`,
/// or an unwrapped `ccache` entry).
#[derive(Clone)]
pub struct KrbTicket {
    /// GSS-KRB5 `AP-REQ` token bytes (as returned by `gss_init_sec_context`).
    pub ap_req: Vec<u8>,
    /// 16-byte session key from the AP-REQ authenticator (subkey when present,
    /// service-ticket session key otherwise).
    pub session_key: [u8; 16],
}

impl KrbTicket {
    pub fn new(ap_req: impl Into<Vec<u8>>, session_key: [u8; 16]) -> Self {
        Self {
            ap_req: ap_req.into(),
            session_key,
        }
    }
}

impl std::fmt::Debug for KrbTicket {
    // Deliberately opaque — never leak the session key or full AP-REQ into
    // logs. Only the AP-REQ length is safe to print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KrbTicket")
            .field("ap_req_len", &self.ap_req.len())
            .field("session_key", &"[redacted; 16 bytes]")
            .finish()
    }
}

// ─── PDU header primitives ──────────────────────────────────────────────────

// Layout mirrors `dcerpc::pdu` (MS-RPCE §2.2.6) but is kept local so the
// Kerberos wire path stays offline-testable — no `dcerpc` dep on the kerberos
// module.

const RPC_VERS: u8 = 5;
const RPC_VERS_MINOR: u8 = 0;
const PTYPE_BIND: u8 = 11;
const PTYPE_AUTH3: u8 = 16;
const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;
const DREP_LE: [u8; 4] = [0x10, 0x00, 0x00, 0x00]; // little-endian, ASCII, IEEE float

fn header_auth(ptype: u8, frag_length: u16, auth_length: u16, call_id: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.push(RPC_VERS);
    h.push(RPC_VERS_MINOR);
    h.push(ptype);
    h.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
    h.extend_from_slice(&DREP_LE);
    h.extend_from_slice(&frag_length.to_le_bytes());
    h.extend_from_slice(&auth_length.to_le_bytes());
    h.extend_from_slice(&call_id.to_le_bytes());
    h
}

/// 8-byte sec_trailer for a Kerberos-authenticated PDU.
///
/// Bytes: `auth_type=0x10 (GSS_KRB5) | auth_level=0x06 (PKT_PRIVACY) |
/// auth_pad_length | reserved | auth_context_id(u32)`. `auth_context_id` is
/// 0 for BIND — the server assigns a value on BIND_ACK.
fn kerberos_sec_trailer(auth_pad_length: u8) -> [u8; 8] {
    [
        RPC_C_AUTHN_GSS_KERBEROS,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        auth_pad_length,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Build the presentation-context list of a BIND: one context offering
/// `syntax_uuid` (interface) + the NDR transfer syntax.
fn bind_body(syntax_uuid: [u8; 16], ver_major: u16, ver_minor: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(72);
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id (server assigns)
    body.push(1); // n_context_elem
    body.push(0);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0);
    body.extend_from_slice(&syntax_uuid);
    body.extend_from_slice(&ver_major.to_le_bytes());
    body.extend_from_slice(&ver_minor.to_le_bytes());
    body.extend_from_slice(&NDR_TRANSFER_SYNTAX_UUID);
    body.extend_from_slice(&2u16.to_le_bytes()); // NDR ver 2.0
    body.extend_from_slice(&0u16.to_le_bytes());
    body
}

// ─── public encoders ────────────────────────────────────────────────────────

/// Build a `BIND` PDU carrying a Kerberos `AP-REQ` verifier for
/// `syntax_uuid` at `ver_major.ver_minor` (for MS-ICPR: pass
/// [`ICPR_SYNTAX_UUID`] with `0, 0`).
///
/// Layout (MS-RPCE §2.2.6.2):
///
/// ```text
///   common header       16 bytes  (ptype=BIND, auth_length=|ap_req|)
///   bind body           bind_body(syntax) — presentation context list
///   sec_trailer          8 bytes  (auth_type=0x10, auth_level=0x06, …)
///   auth_value          ap_req bytes (opaque GSS-KRB5 token)
/// ```
///
/// The `ap_req` slice is the full GSS-wrapped AP-REQ blob (with the RFC 4121
/// GSS-API mech-token OID header). This crate never mints it — plug in a
/// Kerberos toolkit of choice.
pub fn encode_kerberos_bind_pdu(
    call_id: u32,
    syntax_uuid: [u8; 16],
    ver_major: u16,
    ver_minor: u16,
    ap_req: &[u8],
) -> Vec<u8> {
    let body = bind_body(syntax_uuid, ver_major, ver_minor);
    let frag_length = (16 + body.len() + 8 + ap_req.len()) as u16;
    let mut pdu = header_auth(PTYPE_BIND, frag_length, ap_req.len() as u16, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&kerberos_sec_trailer(0));
    pdu.extend_from_slice(ap_req);
    pdu
}

/// Build the `AUTH3` PDU that completes a Kerberos BIND with mutual auth.
///
/// The Windows CA replies to a mutual-auth BIND with an `AP-REP` inside the
/// BIND_ACK's auth_value; the client acknowledges by sending an AUTH3 whose
/// auth_value is empty (or the GSS-continue token for a multi-leg
/// authenticator, which is rare for KRB5). This helper accepts either shape.
pub fn encode_kerberos_auth3_pdu(call_id: u32, follow_up_token: &[u8]) -> Vec<u8> {
    let frag_length = (16 + 4 + 8 + follow_up_token.len()) as u16;
    let mut pdu = header_auth(
        PTYPE_AUTH3,
        frag_length,
        follow_up_token.len() as u16,
        call_id,
    );
    // rpcconn_auth3 4-byte pad (max_xmit/recv, ignored by the server).
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&kerberos_sec_trailer(0));
    pdu.extend_from_slice(follow_up_token);
    pdu
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ap_req(len: usize) -> Vec<u8> {
        // A plausible GSS-KRB5 token prefix: 0x60 (APPLICATION[0]) + length +
        // OID header for 1.2.840.113554.1.2.2 (KRB5). Content past the OID is
        // arbitrary — the encoder treats it as opaque.
        let mut v = vec![
            0x60, 0x82, 0x00, 0x00, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02,
            0x02,
        ];
        v.resize(len, 0xAB);
        v
    }

    #[test]
    fn bind_pdu_has_kerberos_auth_type_in_sec_trailer() {
        let ap_req = fake_ap_req(120);
        let pdu = encode_kerberos_bind_pdu(7, ICPR_SYNTAX_UUID, 0, 0, &ap_req);

        // Common header sanity.
        assert_eq!(pdu[0], 5, "rpc_vers");
        assert_eq!(pdu[2], PTYPE_BIND, "ptype must be BIND");
        assert_eq!(pdu[3], PFC_FIRST_FRAG | PFC_LAST_FRAG, "single-frag flags");
        let frag = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag, pdu.len(), "frag_length matches PDU length");
        let auth_length = u16::from_le_bytes([pdu[10], pdu[11]]) as usize;
        assert_eq!(auth_length, ap_req.len(), "auth_length must equal |AP-REQ|");
        assert_eq!(u32::from_le_bytes(pdu[12..16].try_into().unwrap()), 7);

        // sec_trailer sits immediately before the auth_value.
        let st = pdu.len() - ap_req.len() - 8;
        assert_eq!(
            pdu[st], RPC_C_AUTHN_GSS_KERBEROS,
            "auth_type in sec_trailer must be 0x10 (GSS_KERBEROS), got 0x{:02x}",
            pdu[st]
        );
        assert_eq!(
            pdu[st + 1],
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            "auth_level must be 0x06 (PKT_PRIVACY)"
        );
        assert_eq!(pdu[st + 2], 0, "auth_pad_length");
        assert_eq!(&pdu[st + 4..st + 8], &[0, 0, 0, 0], "auth_context_id = 0");

        // AP-REQ bytes appear verbatim at the tail.
        assert_eq!(&pdu[pdu.len() - ap_req.len()..], &ap_req[..]);
    }

    #[test]
    fn bind_pdu_offers_icpr_and_ndr_syntaxes() {
        let ap_req = fake_ap_req(64);
        let pdu = encode_kerberos_bind_pdu(1, ICPR_SYNTAX_UUID, 0, 0, &ap_req);
        // bind_body layout (see `bind_body`):
        //   max_xmit(2) + max_recv(2) + assoc_group_id(4)
        // + n_context_elem(1) + reserved(1) + reserved(2)
        // + p_cont_id(2) + n_transfer_syn(1) + reserved(1)
        // = 16 bytes → abstract_syntax UUID at body offset 16, absolute 32.
        let abs_off = 16 /* header */ + 16 /* bind_body prologue */;
        assert_eq!(&pdu[abs_off..abs_off + 16], &ICPR_SYNTAX_UUID);
        // NDR syntax immediately after ver_major(2)+ver_minor(2).
        let ndr_off = abs_off + 16 + 4;
        assert_eq!(&pdu[ndr_off..ndr_off + 16], &NDR_TRANSFER_SYNTAX_UUID);
        // And ver_major=2 for the NDR transfer syntax.
        assert_eq!(
            u16::from_le_bytes([pdu[ndr_off + 16], pdu[ndr_off + 17]]),
            2
        );
    }

    #[test]
    fn auth3_pdu_carries_empty_or_followup_token() {
        // Empty token (typical KRB5 mutual-auth confirmation).
        let empty = encode_kerberos_auth3_pdu(9, &[]);
        assert_eq!(empty[2], PTYPE_AUTH3);
        assert_eq!(u16::from_le_bytes([empty[10], empty[11]]), 0);
        assert_eq!(
            u16::from_le_bytes([empty[8], empty[9]]) as usize,
            empty.len()
        );
        // sec_trailer sits right before the (empty) verifier: last 8 bytes.
        let st = empty.len() - 8;
        assert_eq!(empty[st], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(empty[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);

        // Non-empty follow-up (rare for KRB5 but the shape must still be valid).
        let tok = [0xAAu8; 32];
        let with_tok = encode_kerberos_auth3_pdu(9, &tok);
        assert_eq!(
            u16::from_le_bytes([with_tok[10], with_tok[11]]) as usize,
            tok.len()
        );
        assert_eq!(&with_tok[with_tok.len() - tok.len()..], &tok);
    }

    #[test]
    fn ticket_debug_redacts_secrets() {
        let ticket = KrbTicket::new(vec![0xDE; 42], [0xFF; 16]);
        let dbg = format!("{ticket:?}");
        assert!(dbg.contains("ap_req_len: 42"));
        assert!(dbg.contains("redacted"));
        // No raw session-key bytes leaked.
        assert!(!dbg.contains("255, 255, 255"));
    }

    #[test]
    fn icpr_uuid_encoding_matches_canonical_form() {
        // The canonical MS-ICPR interface UUID is
        // 91ae6020-9e3c-11cf-8d7c-00aa00c091be. DCE encoding is
        // little-endian for the first three fields, big-endian for the last
        // two. Pin the exact byte layout so a future refactor can't drift.
        let expected: [u8; 16] = [
            0x20, 0x60, 0xae, 0x91, // data1 (LE)
            0x3c, 0x9e, // data2 (LE)
            0xcf, 0x11, // data3 (LE)
            0x8d, 0x7c, // data4 (BE, node id start)
            0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe, // node id
        ];
        assert_eq!(ICPR_SYNTAX_UUID, expected);
    }
}
