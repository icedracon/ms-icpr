//! RPC client pre-flight tests.
//!
//! `submit_request` is stubbed against real transport (needs a live DC),
//! but the offline pre-flight — CSR shape, schema version,
//! `min_ra_signatures` — is real behavior and worth pinning.

use ms_crtd::{CertTemplate, EnrollmentFlag, NameFlag, Oid, PrivateKeyFlag};
use ms_icpr::{Error, IcprClient};

fn template(name: &str, min_ra: i32) -> CertTemplate {
    CertTemplate {
        name: name.into(),
        oid: Oid::from("1.3.6.1.4.1.311.21.8.1.2"),
        schema_version: 2,
        enrollment_flag: EnrollmentFlag::empty(),
        name_flag: NameFlag::ENROLLEE_SUPPLIES_SUBJECT,
        private_key_flag: PrivateKeyFlag::empty(),
        ekus: vec![Oid::from("1.3.6.1.5.5.7.3.2")], // client auth
        min_ra_signatures: min_ra,
        raw_security_descriptor: None,
    }
}

#[test]
fn submit_rejects_ra_signatures_required() {
    let mut client = IcprClient::stub("corp-CA");
    let csr = vec![0x30, 0x03, 0x02, 0x01, 0x00]; // minimal SEQUENCE
    let err = client
        .submit_request(&template("User-with-RA", 1), &csr)
        .expect_err("template requires RA sig");
    assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    assert!(format!("{err}").contains("RA signature"));
}

#[test]
fn submit_rejects_non_der_csr() {
    let mut client = IcprClient::stub("corp-CA");
    let err = client
        .submit_request(&template("User", 0), &[0xff, 0xff])
        .expect_err("bad csr shape");
    assert!(matches!(err, Error::Invalid(_)));
}

#[test]
fn submit_stub_transport_reports_live_dc_only() {
    let mut client = IcprClient::stub("corp-CA");
    // Valid-looking SEQUENCE, passes pre-flight, then the stub transport
    // is invoked and returns LiveDcOnly.
    let csr = vec![0x30, 0x03, 0x02, 0x01, 0x00];
    let err = client
        .submit_request(&template("User", 0), &csr)
        .expect_err("stub can't reach a DC");
    assert!(matches!(err, Error::LiveDcOnly), "got {err:?}");
}

#[test]
fn client_carries_ca_name() {
    let client = IcprClient::stub("corp-CA");
    assert_eq!(client.ca_name(), "corp-CA");
}
