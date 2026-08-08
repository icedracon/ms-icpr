//! Well-known OIDs used by MS-ICPR / WCCE certificate requests.

/// rsaEncryption — SubjectPublicKeyInfo algorithm identifier for RSA.
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// sha256WithRSAEncryption — signature algorithm on the CSR.
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

/// commonName — X.520 attribute type used in Subject.
pub const AT_COMMON_NAME: &str = "2.5.4.3";

/// PKCS#9 extensionRequest — attribute that carries requested X.509 extensions.
pub const PKCS9_EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";

/// id-ce-subjectAltName — X.509 SubjectAltName extension.
pub const CE_SUBJECT_ALT_NAME: &str = "2.5.29.17";

/// Microsoft userPrincipalName otherName type — the ESC1 impersonation vector.
pub const MS_USER_PRINCIPAL_NAME: &str = "1.3.6.1.4.1.311.20.2.3";
