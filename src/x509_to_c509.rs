//! Convert a real X.509 certificate (PEM or DER) into C509 bytes, via the
//! `--from-json` schema ([`crate::cert_json::JsonCertificate`]) as an
//! intermediate step. Used by the `--from-x509` CLI option.
//!
//! Targets `c509CertificateType = 3` ("DER re-encoded"): the subject public
//! key and the signature value are carried through as opaque bytes exactly
//! as they appear in the DER certificate, with no algorithm-specific
//! repacking (no EC point compression, no RSA exponent elision, no ECDSA
//! DER `SEQUENCE(r, s)` -> raw `r‖s` conversion). This is a deliberate
//! simplification for testing the CLI against real-world certificates, not
//! a byte-accurate implementation of the draft's DER<->C509 conversion
//! rules.
//!
//! Algorithm and RDN-attribute OIDs are mapped to C509 registry ids only
//! for the well-known, unambiguous cases below (backed by named constants
//! from the `oid-registry` crate, not hand-typed OID strings); anything
//! else is reported as an error rather than guessed.

use x509_parser::extensions::{GeneralName as X509GeneralName, ParsedExtension};
use x509_parser::oid_registry::asn1_rs::{Oid, Tag};
use x509_parser::oid_registry::*;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::cert_json::{JsonCertificate, JsonExtension, JsonName, JsonRdnAttribute};

/// `c509CertificateType = 3`, "CBOR re-encoding of a DER-encoded
/// certificate" (Section 3.1).
const CERTIFICATE_TYPE_DER_REENCODED: i32 = 3;

/// `9999-12-31T23:59:59Z`, RFC 5280's "no well-defined expiration date"
/// sentinel, mapped to C509's `validityNotAfter = null`.
const NO_EXPIRATION_TIMESTAMP: i64 = 253_402_300_799;

/// Parse `input` as PEM or DER X.509 and encode it as C509 bytes. `sequence`
/// selects the bare CBOR Sequence form over the default array-wrapped form,
/// same as elsewhere in the CLI.
pub(crate) fn convert_to_bytes(input: &[u8], sequence: bool) -> Result<Vec<u8>, String> {
    let cert = convert(input)?.into_certificate()?;
    Ok(if sequence {
        cert.encode_sequence()
    } else {
        cert.encode()
    })
}

/// Parse `input` as PEM (if it looks like a `-----BEGIN` block) or raw DER,
/// and convert it to the `--from-json` schema.
fn convert(input: &[u8]) -> Result<JsonCertificate, String> {
    let looks_like_pem = input
        .iter()
        .take(1024)
        .copied()
        .collect::<Vec<u8>>()
        .windows(11)
        .any(|w| w == b"-----BEGIN ");
    if looks_like_pem {
        let (pem, _) = Pem::read(std::io::Cursor::new(input))
            .map_err(|e| format!("failed to read PEM: {e}"))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| format!("failed to parse X.509 DER inside PEM: {e}"))?;
        convert_certificate(&cert)
    } else {
        let (_, cert) = X509Certificate::from_der(input)
            .map_err(|e| format!("failed to parse X.509 DER: {e}"))?;
        convert_certificate(&cert)
    }
}

fn convert_certificate(cert: &X509Certificate<'_>) -> Result<JsonCertificate, String> {
    let tbs = &cert.tbs_certificate;

    let not_before = tbs.validity().not_before.timestamp();
    let not_after = tbs.validity().not_after.timestamp();

    let mut extensions = Vec::new();
    if let Some(bc) = tbs
        .basic_constraints()
        .map_err(|e| format!("basicConstraints: {e}"))?
    {
        extensions.push(JsonExtension::BasicConstraints {
            critical: bc.critical,
            ca: bc.value.ca,
            path_len: bc.value.path_len_constraint,
        });
    }
    if let Some(ku) = tbs.key_usage().map_err(|e| format!("keyUsage: {e}"))? {
        extensions.push(JsonExtension::KeyUsage {
            critical: ku.critical,
            value: ku.value.flags as u32,
        });
    }
    if let Some(eku) = tbs
        .extended_key_usage()
        .map_err(|e| format!("extKeyUsage: {e}"))?
    {
        if !eku.value.other.is_empty() {
            return Err(
                "extKeyUsage: OID-form KeyPurposeIds aren't supported by this converter"
                    .to_string(),
            );
        }
        extensions.push(JsonExtension::ExtKeyUsage {
            critical: eku.critical,
            oids: extended_key_usage_ids(eku.value),
        });
    }
    if let Some(san) = tbs
        .subject_alternative_name()
        .map_err(|e| format!("subjectAltName: {e}"))?
    {
        let mut dns_names = Vec::new();
        for name in &san.value.general_names {
            match name {
                X509GeneralName::DNSName(s) => dns_names.push((*s).to_string()),
                other => {
                    return Err(format!(
                        "subjectAltName: only dNSName entries are supported by this converter, found {other:?}"
                    ));
                }
            }
        }
        extensions.push(JsonExtension::SubjectAltName {
            critical: san.critical,
            dns_names,
        });
    }
    if let Some(ext) = tbs
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .map_err(|e| format!("authorityKeyIdentifier: {e}"))?
        && let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension()
    {
        let Some(key_identifier) = &aki.key_identifier else {
            return Err(
                "authorityKeyIdentifier: only the keyIdentifier form is supported by this converter"
                    .to_string(),
            );
        };
        extensions.push(JsonExtension::AuthorityKeyIdentifier {
            critical: ext.critical,
            key_identifier: hex::encode(key_identifier.0),
        });
    }

    Ok(JsonCertificate {
        certificate_type: CERTIFICATE_TYPE_DER_REENCODED,
        serial_number: hex::encode(tbs.raw_serial()),
        issuer_signature_algorithm: signature_algorithm_id(&cert.signature_algorithm.algorithm)?,
        issuer: Some(name_to_json(tbs.issuer())?),
        validity_not_before: rfc3339(not_before)?,
        validity_not_after: if not_after == NO_EXPIRATION_TIMESTAMP {
            None
        } else {
            Some(rfc3339(not_after)?)
        },
        subject: name_to_json(tbs.subject())?,
        subject_public_key_algorithm: public_key_algorithm_id(&tbs.subject_pki.algorithm)?,
        subject_public_key: hex::encode(&tbs.subject_pki.subject_public_key.data),
        extensions,
        issuer_signature_value: hex::encode(&cert.signature_value.data),
    })
}

fn rfc3339(unix_timestamp: i64) -> Result<String, String> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::from_unix_timestamp(unix_timestamp)
        .map_err(|e| format!("timestamp out of range: {e}"))?
        .format(&Rfc3339)
        .map_err(|e| format!("failed to format timestamp: {e}"))
}

/// Section 8.14 "C509 Signature Algorithms Registry" entries this converter
/// recognizes.
fn signature_algorithm_id(oid: &Oid<'_>) -> Result<i32, String> {
    Ok(if *oid == OID_SIG_ECDSA_WITH_SHA256 {
        0
    } else if *oid == OID_SIG_ECDSA_WITH_SHA384 {
        1
    } else if *oid == OID_SIG_ECDSA_WITH_SHA512 {
        2
    } else if *oid == OID_SIG_ED25519 {
        12
    } else if *oid == OID_SIG_ED448 {
        13
    } else if *oid == OID_PKCS1_SHA256WITHRSA {
        23
    } else if *oid == OID_PKCS1_SHA384WITHRSA {
        24
    } else if *oid == OID_PKCS1_SHA512WITHRSA {
        25
    } else {
        return Err(format!(
            "issuerSignatureAlgorithm: unrecognized OID {oid} (this converter only knows a \
             handful of common algorithms; extend `signature_algorithm_id` in x509_to_c509.rs)"
        ));
    })
}

/// Section 8.15 "C509 Public Key Algorithms Registry" entries this
/// converter recognizes.
fn public_key_algorithm_id(
    alg: &x509_parser::x509::AlgorithmIdentifier<'_>,
) -> Result<i32, String> {
    let oid = &alg.algorithm;
    if *oid == OID_PKCS1_RSAENCRYPTION {
        return Ok(0);
    }
    if *oid == OID_SIG_ED25519 {
        return Ok(12);
    }
    if *oid == OID_SIG_ED448 {
        return Ok(13);
    }
    if *oid == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = alg
            .parameters
            .clone()
            .ok_or_else(|| {
                "subjectPublicKeyAlgorithm: EC key is missing its curve OID".to_string()
            })?
            .oid()
            .map_err(|e| format!("subjectPublicKeyAlgorithm: EC curve parameter: {e}"))?;
        return Ok(if curve == OID_EC_P256 {
            1
        } else if curve == OID_NIST_EC_P384 {
            2
        } else if curve == OID_NIST_EC_P521 {
            3
        } else {
            return Err(format!(
                "subjectPublicKeyAlgorithm: unrecognized EC curve OID {curve} (this converter \
                 only knows P-256/P-384/P-521; extend `public_key_algorithm_id` in \
                 x509_to_c509.rs)"
            ));
        });
    }
    Err(format!(
        "subjectPublicKeyAlgorithm: unrecognized OID {oid} (this converter only knows a handful \
         of common algorithms; extend `public_key_algorithm_id` in x509_to_c509.rs)"
    ))
}

/// Section 8.12 "C509 Extended Key Usages Registry" ids for the recognized
/// (non-OID-form) purposes x509-parser exposes as named booleans.
fn extended_key_usage_ids(eku: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> Vec<i32> {
    let mut ids = Vec::new();
    if eku.any {
        ids.push(0);
    }
    if eku.server_auth {
        ids.push(1);
    }
    if eku.client_auth {
        ids.push(2);
    }
    if eku.code_signing {
        ids.push(3);
    }
    if eku.email_protection {
        ids.push(4);
    }
    if eku.time_stamping {
        ids.push(8);
    }
    if eku.ocsp_signing {
        ids.push(9);
    }
    ids
}

/// Section 8.6 "C509 RDN Attributes Registry" entries this converter
/// recognizes.
fn rdn_attribute_id(oid: &Oid<'_>) -> Option<u16> {
    Some(if *oid == OID_PKCS9_EMAIL_ADDRESS {
        0
    } else if *oid == OID_X509_COMMON_NAME {
        1
    } else if *oid == OID_X509_SURNAME {
        2
    } else if *oid == OID_X509_SERIALNUMBER {
        3
    } else if *oid == OID_X509_COUNTRY_NAME {
        4
    } else if *oid == OID_X509_LOCALITY_NAME {
        5
    } else if *oid == OID_X509_STATE_OR_PROVINCE_NAME {
        6
    } else if *oid == OID_X509_STREET_ADDRESS {
        7
    } else if *oid == OID_X509_ORGANIZATION_NAME {
        8
    } else if *oid == OID_X509_ORGANIZATIONAL_UNIT {
        9
    } else if *oid == OID_X509_TITLE {
        10
    } else if *oid == OID_X509_BUSINESS_CATEGORY {
        11
    } else if *oid == OID_X509_POSTAL_CODE {
        12
    } else if *oid == OID_X509_GIVEN_NAME {
        13
    } else if *oid == OID_X509_INITIALS {
        14
    } else if *oid == OID_X509_GENERATION_QUALIFIER {
        15
    } else if *oid == OID_X509_DN_QUALIFIER {
        16
    } else if *oid == OID_DOMAIN_COMPONENT {
        22
    } else if *oid == OID_X509_NAME {
        25
    } else if *oid == OID_USERID {
        28
    } else if *oid == OID_PKCS9_UNSTRUCTURED_NAME {
        29
    } else {
        return None;
    })
}

fn name_to_json(name: &x509_parser::x509::X509Name<'_>) -> Result<JsonName, String> {
    let mut attrs = Vec::new();
    for attr in name.iter_attributes() {
        let id = rdn_attribute_id(attr.attr_type()).ok_or_else(|| {
            format!(
                "name attribute OID {} isn't supported by this converter (extend \
                 `rdn_attribute_id` in x509_to_c509.rs)",
                attr.attr_type()
            )
        })?;
        let value = attr
            .as_str()
            .map_err(|e| format!("name attribute OID {}: {e}", attr.attr_type()))?;
        attrs.push(JsonRdnAttribute {
            id,
            printable_string: attr.attr_value().tag() == Tag::PrintableString,
            value: value.to_string(),
        });
    }
    Ok(JsonName::Attributes(attrs))
}
