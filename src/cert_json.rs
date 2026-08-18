//! Hand-authored JSON schema for building a [`C509Certificate`] from a
//! human-edited file (used by the CLI's `--from-json` option). This is *not*
//! a mechanical mirror of the crate's CBOR types: dates are RFC 3339
//! strings, byte fields are hex strings, and only the core `TBSCertificate`
//! fields plus a handful of the most common extensions are supported.

use c509_cert::{
    AlgorithmIdentifier, AuthorityKeyIdentifier, BasicConstraints, C509Certificate, ExtKeyUsage,
    Extension, ExtensionValue, Extensions, GeneralName, GeneralNameValue, IntOrOid, MacAddr, Name,
    RdnAttribute, SpecialText, TbsCertificate,
};
use num_bigint::BigUint;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Registry ids (Section 8.8 "C509 Extensions Registry") for the extensions
/// this schema understands.
const EXT_KEY_USAGE_ID: i32 = 2;
const EXT_SUBJECT_ALT_NAME_ID: i32 = 3;
const EXT_BASIC_CONSTRAINTS_ID: i32 = 4;
const EXT_AUTHORITY_KEY_IDENTIFIER_ID: i32 = 7;
const EXT_EXT_KEY_USAGE_ID: i32 = 8;

/// Registry id for `commonName` (Section 8.6), used for the plain-string
/// form of [`JsonName`].
const COMMON_NAME_ID: u16 = 1;

/// `dNSName` (Section 8.13 "C509 General Names Registry").
const GENERAL_NAME_DNS: i32 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonCertificate {
    certificate_type: i32,
    serial_number: String,
    issuer_signature_algorithm: i32,
    #[serde(default)]
    issuer: Option<JsonName>,
    validity_not_before: String,
    #[serde(default)]
    validity_not_after: Option<String>,
    subject: JsonName,
    subject_public_key_algorithm: i32,
    subject_public_key: String,
    #[serde(default)]
    extensions: Vec<JsonExtension>,
    issuer_signature_value: String,
}

/// Either a bare string (compact single `commonName`) or a full list of RDN
/// attributes.
#[derive(Deserialize)]
#[serde(untagged)]
enum JsonName {
    CommonName(String),
    Attributes(Vec<JsonRdnAttribute>),
}

#[derive(Deserialize)]
struct JsonRdnAttribute {
    /// Registry id, Section 8.6 "C509 RDN Attributes Registry".
    id: u16,
    #[serde(default)]
    printable_string: bool,
    value: String,
}

/// Only the most common extensions are supported; anything else must be
/// added here as this schema grows.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum JsonExtension {
    BasicConstraints {
        #[serde(default)]
        critical: bool,
        #[serde(default)]
        ca: bool,
        #[serde(default)]
        path_len: Option<u32>,
    },
    KeyUsage {
        #[serde(default)]
        critical: bool,
        value: u32,
    },
    SubjectAltName {
        #[serde(default)]
        critical: bool,
        dns_names: Vec<String>,
    },
    /// Only the bare `keyIdentifier` form; `cert_issuer`/`cert_serial`
    /// aren't exposed by this schema yet.
    AuthorityKeyIdentifier {
        #[serde(default)]
        critical: bool,
        key_identifier: String,
    },
    /// Registered `KeyPurposeId`s only; OID-form purposes aren't exposed by
    /// this schema yet.
    ExtKeyUsage {
        #[serde(default)]
        critical: bool,
        oids: Vec<i32>,
    },
}

/// Parse a whitespace-tolerant hex string into bytes.
fn hex_bytes(field: &str, s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).map_err(|e| format!("{field}: invalid hex: {e}"))
}

/// A bare string becomes a [`SpecialText::Mac`] if it parses as a MAC
/// address, otherwise a [`SpecialText::Text`].
fn special_text(s: &str) -> SpecialText {
    match s.parse::<MacAddr>() {
        Ok(mac) => SpecialText::Mac(mac),
        Err(_) => SpecialText::Text(s.to_string()),
    }
}

impl JsonName {
    fn into_name(self) -> Name {
        match self {
            JsonName::CommonName(s) => Name(vec![RdnAttribute::Registered {
                id: COMMON_NAME_ID,
                printable_string: false,
                value: special_text(&s),
            }]),
            JsonName::Attributes(attrs) => Name(
                attrs
                    .into_iter()
                    .map(|a| RdnAttribute::Registered {
                        id: a.id,
                        printable_string: a.printable_string,
                        value: special_text(&a.value),
                    })
                    .collect(),
            ),
        }
    }
}

impl JsonExtension {
    fn into_extension(self) -> Result<Extension, String> {
        let (id, critical, value) = match self {
            JsonExtension::BasicConstraints {
                critical,
                ca,
                path_len,
            } => (
                EXT_BASIC_CONSTRAINTS_ID,
                critical,
                ExtensionValue::BasicConstraints(if ca {
                    BasicConstraints::Ca { path_len }
                } else {
                    BasicConstraints::NotCa
                }),
            ),
            JsonExtension::KeyUsage { critical, value } => {
                (EXT_KEY_USAGE_ID, critical, ExtensionValue::KeyUsage(value))
            }
            JsonExtension::SubjectAltName {
                critical,
                dns_names,
            } => (
                EXT_SUBJECT_ALT_NAME_ID,
                critical,
                ExtensionValue::SubjectAltName(
                    dns_names
                        .into_iter()
                        .map(|s| GeneralName {
                            kind: GENERAL_NAME_DNS,
                            value: GeneralNameValue::DnsName(s),
                        })
                        .collect(),
                ),
            ),
            JsonExtension::AuthorityKeyIdentifier {
                critical,
                key_identifier,
            } => (
                EXT_AUTHORITY_KEY_IDENTIFIER_ID,
                critical,
                ExtensionValue::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                    key_identifier: hex_bytes(
                        "authority_key_identifier.key_identifier",
                        &key_identifier,
                    )?,
                    cert_issuer: None,
                    cert_serial: None,
                }),
            ),
            JsonExtension::ExtKeyUsage { critical, oids } => (
                EXT_EXT_KEY_USAGE_ID,
                critical,
                ExtensionValue::ExtKeyUsage(ExtKeyUsage(
                    oids.into_iter().map(IntOrOid::Int).collect(),
                )),
            ),
        };
        Ok(Extension {
            id: IntOrOid::Int(id),
            critical,
            value,
        })
    }
}

impl JsonCertificate {
    pub fn into_certificate(self) -> Result<C509Certificate, String> {
        let certificate_serial_number =
            BigUint::from_bytes_be(&hex_bytes("serial_number", &self.serial_number)?);

        let validity_not_before = OffsetDateTime::parse(&self.validity_not_before, &Rfc3339)
            .map_err(|e| format!("validity_not_before: {e}"))?;
        let validity_not_after = self
            .validity_not_after
            .as_deref()
            .map(|s| OffsetDateTime::parse(s, &Rfc3339))
            .transpose()
            .map_err(|e| format!("validity_not_after: {e}"))?;

        let subject_public_key = hex_bytes("subject_public_key", &self.subject_public_key)?;
        let issuer_signature_value =
            hex_bytes("issuer_signature_value", &self.issuer_signature_value)?;

        let extensions = self
            .extensions
            .into_iter()
            .map(JsonExtension::into_extension)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(C509Certificate {
            tbs: TbsCertificate {
                c509_certificate_type: self.certificate_type,
                certificate_serial_number,
                issuer_signature_algorithm: AlgorithmIdentifier::Int(
                    self.issuer_signature_algorithm,
                ),
                issuer: self.issuer.map(JsonName::into_name),
                validity_not_before,
                validity_not_after,
                subject: self.subject.into_name(),
                subject_public_key_algorithm: AlgorithmIdentifier::Int(
                    self.subject_public_key_algorithm,
                ),
                subject_public_key,
                extensions: Extensions(extensions),
            },
            issuer_signature_value,
        })
    }
}
