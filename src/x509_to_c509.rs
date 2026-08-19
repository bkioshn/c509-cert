//! Convert a real X.509 certificate (PEM or DER) into a [`C509Certificate`],
//! via [`from_x509`].
//!
//! Targets `c509CertificateType = 3` ("DER re-encoded"): the subject public
//! key and the signature value are carried through as opaque bytes exactly
//! as they appear in the DER certificate, with no algorithm-specific
//! repacking (no EC point compression, no RSA exponent elision, no ECDSA
//! DER `SEQUENCE(r, s)` -> raw `r‖s` conversion). This is a deliberate
//! simplification, not a byte-accurate implementation of the draft's
//! DER<->C509 conversion rules.
//!
//! Algorithm and RDN-attribute OIDs are mapped to C509 registry ids only
//! for the well-known, unambiguous cases below (backed by named constants
//! from the `oid-registry` crate, not hand-typed OID strings); anything
//! else is reported as an [`Error::X509`] rather than guessed.

use macaddr::MacAddr;
use num_bigint::BigUint;
use x509_parser::extensions::{GeneralName as X509GeneralName, ParsedExtension};
use x509_parser::oid_registry::asn1_rs::{Oid, Tag};
use x509_parser::oid_registry::*;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate as X509Cert};
use x509_parser::x509::X509Name;

use crate::algorithm::AlgorithmIdentifier;
use crate::common::{IntOrOid, SpecialText};
use crate::error::Error;
use crate::error::Result;
use crate::extensions::{
    AuthorityKeyIdentifier, BasicConstraints, ExtKeyUsage, Extension, ExtensionValue, Extensions,
    GeneralName, GeneralNameValue,
};
use crate::name::{Name, RdnAttribute};
use crate::{C509Certificate, TbsCertificate};

/// `c509CertificateType = 3`, "CBOR re-encoding of a DER-encoded
/// certificate" (Section 3.1).
const CERTIFICATE_TYPE_DER_REENCODED: i32 = 3;

/// `9999-12-31T23:59:59Z`, RFC 5280's "no well-defined expiration date"
/// sentinel, mapped to C509's `validityNotAfter = null`.
const NO_EXPIRATION_TIMESTAMP: i64 = 253_402_300_799;

/// `dNSName` (Section 8.13 "C509 General Names Registry").
const GENERAL_NAME_DNS: i32 = 2;

/// Registry ids (Section 8.8 "C509 Extensions Registry") for the extensions
/// this converter recognizes.
const EXT_KEY_USAGE_ID: i32 = 2;
const EXT_SUBJECT_ALT_NAME_ID: i32 = 3;
const EXT_BASIC_CONSTRAINTS_ID: i32 = 4;
const EXT_AUTHORITY_KEY_IDENTIFIER_ID: i32 = 7;
const EXT_EXT_KEY_USAGE_ID: i32 = 8;

/// Parse `input` as PEM (if it looks like a `-----BEGIN` block) or raw DER
/// X.509, and convert it straight into a [`C509Certificate`].
///
/// See the module docs for exactly what's supported.
pub fn from_x509(input: &[u8]) -> Result<C509Certificate> {
    let looks_like_pem = input[..input.len().min(1024)]
        .windows(11)
        .any(|w| w == b"-----BEGIN ");
    if looks_like_pem {
        let (pem, _) =
            Pem::read(std::io::Cursor::new(input)).map_err(|e| x509_err("failed to read PEM", e))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| x509_err("failed to parse X.509 DER inside PEM", e))?;
        convert_certificate(&cert)
    } else {
        let (_, cert) =
            X509Cert::from_der(input).map_err(|e| x509_err("failed to parse X.509 DER", e))?;
        convert_certificate(&cert)
    }
}

fn x509_err(context: &str, e: impl std::fmt::Display) -> Error {
    Error::X509(format!("{context}: {e}"))
}

fn convert_certificate(cert: &X509Cert<'_>) -> Result<C509Certificate> {
    let tbs = &cert.tbs_certificate;
    let validity = tbs.validity();

    let mut extensions = Vec::new();
    if let Some(bc) = tbs
        .basic_constraints()
        .map_err(|e| x509_err("basicConstraints", e))?
    {
        extensions.push(Extension {
            id: IntOrOid::Int(EXT_BASIC_CONSTRAINTS_ID),
            critical: bc.critical,
            value: ExtensionValue::BasicConstraints(if bc.value.ca {
                BasicConstraints::Ca {
                    path_len: bc.value.path_len_constraint,
                }
            } else {
                BasicConstraints::NotCa
            }),
        });
    }
    if let Some(ku) = tbs.key_usage().map_err(|e| x509_err("keyUsage", e))? {
        extensions.push(Extension {
            id: IntOrOid::Int(EXT_KEY_USAGE_ID),
            critical: ku.critical,
            value: ExtensionValue::KeyUsage(ku.value.flags as u32),
        });
    }
    if let Some(eku) = tbs
        .extended_key_usage()
        .map_err(|e| x509_err("extKeyUsage", e))?
    {
        if !eku.value.other.is_empty() {
            return Err(Error::X509(
                "extKeyUsage: OID-form KeyPurposeIds aren't supported by this converter"
                    .to_string(),
            ));
        }
        extensions.push(Extension {
            id: IntOrOid::Int(EXT_EXT_KEY_USAGE_ID),
            critical: eku.critical,
            value: ExtensionValue::ExtKeyUsage(ExtKeyUsage(
                extended_key_usage_ids(eku.value)
                    .into_iter()
                    .map(IntOrOid::Int)
                    .collect(),
            )),
        });
    }
    if let Some(san) = tbs
        .subject_alternative_name()
        .map_err(|e| x509_err("subjectAltName", e))?
    {
        let mut names = Vec::new();
        for name in &san.value.general_names {
            match name {
                X509GeneralName::DNSName(s) => names.push(GeneralName {
                    kind: GENERAL_NAME_DNS,
                    value: GeneralNameValue::DnsName((*s).to_string()),
                }),
                other => {
                    return Err(Error::X509(format!(
                        "subjectAltName: only dNSName entries are supported by this converter, found {other:?}"
                    )));
                }
            }
        }
        extensions.push(Extension {
            id: IntOrOid::Int(EXT_SUBJECT_ALT_NAME_ID),
            critical: san.critical,
            value: ExtensionValue::SubjectAltName(names),
        });
    }
    if let Some(ext) = tbs
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .map_err(|e| x509_err("authorityKeyIdentifier", e))?
    {
        let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() else {
            return Err(Error::X509(format!(
                "authorityKeyIdentifier: could not parse this extension's form ({:?})",
                ext.parsed_extension()
            )));
        };
        let Some(key_identifier) = &aki.key_identifier else {
            return Err(Error::X509(
                "authorityKeyIdentifier: only the keyIdentifier form is supported by this converter"
                    .to_string(),
            ));
        };
        extensions.push(Extension {
            id: IntOrOid::Int(EXT_AUTHORITY_KEY_IDENTIFIER_ID),
            critical: ext.critical,
            value: ExtensionValue::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                key_identifier: key_identifier.0.to_vec(),
                cert_issuer: None,
                cert_serial: None,
            }),
        });
    }

    let validity_not_after = if validity.not_after.timestamp() == NO_EXPIRATION_TIMESTAMP {
        None
    } else {
        Some(validity.not_after.to_datetime())
    };

    Ok(C509Certificate {
        tbs: TbsCertificate {
            c509_certificate_type: CERTIFICATE_TYPE_DER_REENCODED,
            certificate_serial_number: BigUint::from_bytes_be(tbs.raw_serial()),
            issuer_signature_algorithm: AlgorithmIdentifier::Int(signature_algorithm_id(
                &cert.signature_algorithm.algorithm,
            )?),
            issuer: Some(name_to_rdn(tbs.issuer())?),
            validity_not_before: validity.not_before.to_datetime(),
            validity_not_after,
            subject: name_to_rdn(tbs.subject())?,
            subject_public_key_algorithm: AlgorithmIdentifier::Int(public_key_algorithm_id(
                &tbs.subject_pki.algorithm,
            )?),
            subject_public_key: tbs.subject_pki.subject_public_key.data.to_vec(),
            extensions: Extensions(extensions),
        },
        issuer_signature_value: cert.signature_value.data.to_vec(),
    })
}

/// Look up `oid` in a `(Oid, value)` table, returning the mapped value if
/// found. Shared by every OID->registry-id mapping in this file so adding a
/// new recognized OID is a one-line table edit.
fn lookup_oid<T: Copy>(oid: &Oid<'_>, table: &[(Oid<'static>, T)]) -> Option<T> {
    table.iter().find(|(o, _)| o == oid).map(|(_, v)| *v)
}

/// Section 8.14 "C509 Signature Algorithms Registry" entries this converter
/// recognizes.
const SIGNATURE_ALGORITHM_OIDS: &[(Oid<'static>, i32)] = &[
    (OID_SIG_ECDSA_WITH_SHA256, 0),
    (OID_SIG_ECDSA_WITH_SHA384, 1),
    (OID_SIG_ECDSA_WITH_SHA512, 2),
    (OID_SIG_ED25519, 12),
    (OID_SIG_ED448, 13),
    (OID_PKCS1_SHA256WITHRSA, 23),
    (OID_PKCS1_SHA384WITHRSA, 24),
    (OID_PKCS1_SHA512WITHRSA, 25),
];

fn signature_algorithm_id(oid: &Oid<'_>) -> Result<i32> {
    lookup_oid(oid, SIGNATURE_ALGORITHM_OIDS).ok_or_else(|| {
        Error::X509(format!(
            "issuerSignatureAlgorithm: unrecognized OID {oid} (this converter only knows a \
             handful of common algorithms; extend SIGNATURE_ALGORITHM_OIDS in x509_to_c509.rs)"
        ))
    })
}

/// Section 8.15 "C509 Public Key Algorithms Registry" entries this
/// converter recognizes.
const PUBLIC_KEY_ALGORITHM_OIDS: &[(Oid<'static>, i32)] = &[
    (OID_PKCS1_RSAENCRYPTION, 0),
    (OID_SIG_ED25519, 12),
    (OID_SIG_ED448, 13),
];

/// EC curves this converter recognizes for the `id-ecPublicKey` algorithm.
const EC_CURVE_OIDS: &[(Oid<'static>, i32)] = &[
    (OID_EC_P256, 1),
    (OID_NIST_EC_P384, 2),
    (OID_NIST_EC_P521, 3),
];

fn public_key_algorithm_id(alg: &x509_parser::x509::AlgorithmIdentifier<'_>) -> Result<i32> {
    let oid = &alg.algorithm;
    if let Some(id) = lookup_oid(oid, PUBLIC_KEY_ALGORITHM_OIDS) {
        return Ok(id);
    }
    if *oid == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = alg
            .parameters
            .clone()
            .ok_or_else(|| {
                Error::X509("subjectPublicKeyAlgorithm: EC key is missing its curve OID".to_string())
            })?
            .oid()
            .map_err(|e| x509_err("subjectPublicKeyAlgorithm: EC curve parameter", e))?;
        return lookup_oid(&curve, EC_CURVE_OIDS).ok_or_else(|| {
            Error::X509(format!(
                "subjectPublicKeyAlgorithm: unrecognized EC curve OID {curve} (this converter \
                 only knows P-256/P-384/P-521; extend EC_CURVE_OIDS in x509_to_c509.rs)"
            ))
        });
    }
    Err(Error::X509(format!(
        "subjectPublicKeyAlgorithm: unrecognized OID {oid} (this converter only knows a handful \
         of common algorithms; extend PUBLIC_KEY_ALGORITHM_OIDS in x509_to_c509.rs)"
    )))
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
const RDN_ATTRIBUTE_OIDS: &[(Oid<'static>, u16)] = &[
    (OID_PKCS9_EMAIL_ADDRESS, 0),
    (OID_X509_COMMON_NAME, 1),
    (OID_X509_SURNAME, 2),
    (OID_X509_SERIALNUMBER, 3),
    (OID_X509_COUNTRY_NAME, 4),
    (OID_X509_LOCALITY_NAME, 5),
    (OID_X509_STATE_OR_PROVINCE_NAME, 6),
    (OID_X509_STREET_ADDRESS, 7),
    (OID_X509_ORGANIZATION_NAME, 8),
    (OID_X509_ORGANIZATIONAL_UNIT, 9),
    (OID_X509_TITLE, 10),
    (OID_X509_BUSINESS_CATEGORY, 11),
    (OID_X509_POSTAL_CODE, 12),
    (OID_X509_GIVEN_NAME, 13),
    (OID_X509_INITIALS, 14),
    (OID_X509_GENERATION_QUALIFIER, 15),
    (OID_X509_DN_QUALIFIER, 16),
    (OID_DOMAIN_COMPONENT, 22),
    (OID_X509_NAME, 25),
    (OID_USERID, 28),
    (OID_PKCS9_UNSTRUCTURED_NAME, 29),
];

fn rdn_attribute_id(oid: &Oid<'_>) -> Option<u16> {
    lookup_oid(oid, RDN_ATTRIBUTE_OIDS)
}

/// A bare RDN attribute value becomes a [`SpecialText::Mac`] if it parses as
/// a MAC address, otherwise a [`SpecialText::Text`].
fn special_text(s: &str) -> SpecialText {
    match s.parse::<MacAddr>() {
        Ok(mac) => SpecialText::Mac(mac),
        Err(_) => SpecialText::Text(s.to_string()),
    }
}

fn name_to_rdn(name: &X509Name<'_>) -> Result<Name> {
    let mut attrs = Vec::new();
    for attr in name.iter_attributes() {
        let id = rdn_attribute_id(attr.attr_type()).ok_or_else(|| {
            Error::X509(format!(
                "name attribute OID {} isn't supported by this converter (extend \
                 `rdn_attribute_id` in x509_to_c509.rs)",
                attr.attr_type()
            ))
        })?;
        let value = attr
            .as_str()
            .map_err(|e| x509_err(&format!("name attribute OID {}", attr.attr_type()), e))?;
        attrs.push(RdnAttribute::Registered {
            id,
            printable_string: attr.attr_value().tag() == Tag::PrintableString,
            value: special_text(value),
        });
    }
    Ok(Name(attrs))
}
