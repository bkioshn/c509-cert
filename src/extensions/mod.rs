//! X.509 extension encoding (Section 3.1.10 / Section 3.3).
//!
//! ```text
//! Extensions = [ * Extension ] / int
//!
//! Extension = (
//!     ( extensionID: int, extensionValue: Defined ) //
//!     ( extensionID: ~oid, extensionValue: bytes / [ bytes ] )
//! )
//! ```
//!
//! Every extension listed in Section 3.3 gets a typed [`ExtensionValue`]
//! variant; anything else (an unrecognized int `extensionID`, or any
//! `~oid`-identified extension) is kept as [`ExtensionValue::Raw`] — the
//! undecoded DER `extnValue` bytes for the oid form, or the raw CBOR item
//! bytes for an unrecognized int form.

pub mod ip_addr;

mod access_description;
mod authority_key_identifier;
mod basic_constraints;
mod distribution_point;
mod ext_key_usage;
mod general_name;
mod name_constraints;
mod policy;
mod subject_directory_attributes;

pub use access_description::AccessDescription;
pub use authority_key_identifier::AuthorityKeyIdentifier;
pub use basic_constraints::BasicConstraints;
pub use distribution_point::DistributionPointName;
pub use ext_key_usage::ExtKeyUsage;
pub use general_name::{GeneralName, GeneralNameValue};
pub use name_constraints::NameConstraints;
pub use policy::{
    CertificatePolicies, PolicyConstraints, PolicyIdentifier, PolicyMappings, PolicyQualifierInfo,
};
pub use subject_directory_attributes::{RDNAttributes, SubjectDirectoryAttributes};

use general_name::{decode_alt_name, encode_alt_name};
use ip_addr::{AsIdOrRange, IpAddressFamily};
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::common::{self, IntOrOid};
use crate::error::{Error, Result};

// =============================== ExtensionValue ================================

/// An extension value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionValue {
    /// id 1
    SubjectKeyIdentifier(Vec<u8>),
    /// id 2 — `KeyUsage` BIT STRING interpreted as an unsigned int (network
    /// byte order).
    KeyUsage(u32),
    /// id 3
    SubjectAltName(Vec<GeneralName>),
    /// id 4
    BasicConstraints(BasicConstraints),
    /// id 5
    CrlDistributionPoints(Vec<DistributionPointName>),
    /// id 6
    CertificatePolicies(CertificatePolicies),
    /// id 7
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    /// id 8
    ExtKeyUsage(ExtKeyUsage),
    /// id 9
    AuthorityInfoAccess(Vec<AccessDescription>),
    /// id 24
    SubjectDirectoryAttributes(SubjectDirectoryAttributes),
    /// id 25
    IssuerAltName(Vec<GeneralName>),
    /// id 26
    NameConstraints(NameConstraints),
    /// id 27
    PolicyMappings(PolicyMappings),
    /// id 28
    PolicyConstraints(PolicyConstraints),
    /// id 29
    FreshestCrl(Vec<DistributionPointName>),
    /// id 30
    InhibitAnyPolicy(u32),
    /// id 31
    SubjectInfoAccess(Vec<AccessDescription>),
    /// id 32 (`id-pe-ipAddrBlocks`, RFC 3779)
    IpAddrBlocks(Vec<IpAddressFamily>),
    /// id 33 (`id-pe-autonomousSysIds`, RFC 3779)
    AsIdentifiers(Option<Vec<AsIdOrRange>>),
    /// id 34 (`id-pe-ipAddrBlocks-v2`, RFC 8360)
    IpAddrBlocksV2(Vec<IpAddressFamily>),
    /// id 35 (`id-pe-autonomousSysIds-v2`, RFC 8360)
    AsIdentifiersV2(Option<Vec<AsIdOrRange>>),
    /// id 36 (`id-pkix-ocsp-nocheck`)
    OcspNoCheck,
    /// id 38 (`id-pe-tlsfeature`)
    TlsFeatures(Vec<u32>),
    /// Any int `extensionID` not special-cased above, or any `~oid`
    /// extension: the raw undecoded value (DER `extnValue` bytes for the
    /// oid form, raw CBOR item bytes for the int form).
    Raw(Vec<u8>),
}

impl ExtensionValue {
    /// Decode an extension value, given its registry `id`.
    fn decode(id: u32, d: &mut Decoder<'_>) -> Result<Self> {
        Ok(match id {
            1 => ExtensionValue::SubjectKeyIdentifier(d.bytes()?.to_vec()),
            2 => ExtensionValue::KeyUsage(d.u32()?),
            3 => ExtensionValue::SubjectAltName(decode_alt_name(d)?),
            4 => ExtensionValue::BasicConstraints(BasicConstraints::decode(d)?),
            5 => ExtensionValue::CrlDistributionPoints(DistributionPointName::decode(d)?),
            6 => ExtensionValue::CertificatePolicies(CertificatePolicies::decode(d)?),
            7 => ExtensionValue::AuthorityKeyIdentifier(AuthorityKeyIdentifier::decode(d)?),
            8 => ExtensionValue::ExtKeyUsage(ExtKeyUsage::decode(d)?),
            9 => ExtensionValue::AuthorityInfoAccess(AccessDescription::decode(d)?),
            24 => {
                ExtensionValue::SubjectDirectoryAttributes(SubjectDirectoryAttributes::decode(d)?)
            }
            25 => ExtensionValue::IssuerAltName(decode_alt_name(d)?),
            26 => ExtensionValue::NameConstraints(NameConstraints::decode(d)?),
            27 => ExtensionValue::PolicyMappings(PolicyMappings::decode(d)?),
            28 => ExtensionValue::PolicyConstraints(PolicyConstraints::decode(d)?),
            29 => ExtensionValue::FreshestCrl(DistributionPointName::decode(d)?),
            30 => ExtensionValue::InhibitAnyPolicy(d.u32()?),
            31 => ExtensionValue::SubjectInfoAccess(AccessDescription::decode(d)?),
            32 => ExtensionValue::IpAddrBlocks(ip_addr::decode_ip_address_families(d)?),
            33 => ExtensionValue::AsIdentifiers(ip_addr::decode_as_identifiers(d)?),
            34 => ExtensionValue::IpAddrBlocksV2(ip_addr::decode_ip_address_families(d)?),
            35 => ExtensionValue::AsIdentifiersV2(ip_addr::decode_as_identifiers(d)?),
            36 => {
                d.null()?;
                ExtensionValue::OcspNoCheck
            }
            38 => ExtensionValue::TlsFeatures(d.decode()?),
            _ => ExtensionValue::Raw(common::raw_item(d)?),
        })
    }

    /// Encode an extension value.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            ExtensionValue::SubjectKeyIdentifier(b) => {
                e.bytes(b)?;
            }
            ExtensionValue::KeyUsage(n) => {
                e.u32(*n)?;
            }
            ExtensionValue::SubjectAltName(names) | ExtensionValue::IssuerAltName(names) => {
                encode_alt_name(names, e)?;
            }
            ExtensionValue::BasicConstraints(bc) => bc.encode(e)?,
            ExtensionValue::CrlDistributionPoints(dp) | ExtensionValue::FreshestCrl(dp) => {
                DistributionPointName::encode(dp, e)?;
            }
            ExtensionValue::CertificatePolicies(v) => v.encode(e)?,
            ExtensionValue::AuthorityKeyIdentifier(v) => v.encode(e)?,
            ExtensionValue::ExtKeyUsage(v) => v.encode(e)?,
            ExtensionValue::AuthorityInfoAccess(v) | ExtensionValue::SubjectInfoAccess(v) => {
                AccessDescription::encode(v, e)?;
            }
            ExtensionValue::SubjectDirectoryAttributes(v) => v.encode(e)?,
            ExtensionValue::NameConstraints(v) => v.encode(e)?,
            ExtensionValue::PolicyMappings(v) => v.encode(e)?,
            ExtensionValue::PolicyConstraints(v) => v.encode(e)?,
            ExtensionValue::InhibitAnyPolicy(n) => {
                e.u32(*n)?;
            }
            ExtensionValue::IpAddrBlocks(v) | ExtensionValue::IpAddrBlocksV2(v) => {
                ip_addr::encode_ip_address_families(v, e)?;
            }
            ExtensionValue::AsIdentifiers(v) | ExtensionValue::AsIdentifiersV2(v) => {
                ip_addr::encode_as_identifiers(v, e)?;
            }
            ExtensionValue::OcspNoCheck => {
                e.null()?;
            }
            ExtensionValue::TlsFeatures(v) => {
                e.encode(v)?;
            }
            ExtensionValue::Raw(bytes) => common::write_raw(e, bytes)?,
        }
        Ok(())
    }
}

// ================================= Extension ===================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The registry id (Section 8.8) or OID of this extension. Note the
    /// criticality *sign* used on the wire is not folded in here; see
    /// [`Extension::critical`].
    pub id: IntOrOid,
    pub critical: bool,
    pub value: ExtensionValue,
}

impl Extension {
    /// Decode an `Extension`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Bytes => {
                let oid = common::decode_oid(d)?;
                let (critical, raw) = match d.datatype()? {
                    Type::Array | Type::ArrayIndef => {
                        common::expect_array_len(d, 1)?;
                        (true, d.bytes()?.to_vec())
                    }
                    _ => (false, d.bytes()?.to_vec()),
                };
                Ok(Extension {
                    id: IntOrOid::Oid(oid),
                    critical,
                    value: ExtensionValue::Raw(raw),
                })
            }
            _ => {
                let raw_id = d.i32()?;
                let critical = raw_id < 0;
                let id = raw_id.unsigned_abs();
                let value = ExtensionValue::decode(id, d)?;
                Ok(Extension {
                    id: IntOrOid::Int(id as i32),
                    critical,
                    value,
                })
            }
        }
    }

    /// Encode an `Extension`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match &self.id {
            IntOrOid::Int(id) => {
                let signed = if self.critical { -(*id) } else { *id };
                e.i32(signed)?;
                self.value.encode(e)?;
            }
            IntOrOid::Oid(oid) => {
                e.bytes(&common::oid_bytes(oid))?;
                let raw = match &self.value {
                    ExtensionValue::Raw(b) => b.as_slice(),
                    _ => {
                        return Err(minicbor::encode::Error::message(
                            "oid-identified extensions must use ExtensionValue::Raw",
                        ));
                    }
                };
                if self.critical {
                    e.array(1)?;
                    e.bytes(raw)?;
                } else {
                    e.bytes(raw)?;
                }
            }
        }
        Ok(())
    }
}

// ================================= Extensions ===================================

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions(pub Vec<Extension>);

impl Extensions {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => {
                let len = common::definite_array_len(d)?;
                if len % 2 != 0 {
                    return Err(Error::malformed(
                        "Extensions array must have an even number of elements",
                    ));
                }
                let mut out = Vec::with_capacity((len / 2) as usize);
                for _ in 0..(len / 2) {
                    out.push(Extension::decode(d)?);
                }
                Ok(Extensions(out))
            }
            // Compact single-extension shortcut, only defined for keyUsage
            // (registry id 2): sign = criticality, absolute value = the
            // KeyUsage bitmask.
            _ => {
                let raw = d.i32()?;
                let critical = raw < 0;
                let value = raw.unsigned_abs();
                Ok(Extensions(vec![Extension {
                    id: IntOrOid::Int(2),
                    critical,
                    value: ExtensionValue::KeyUsage(value),
                }]))
            }
        }
    }

    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        if self.0.len() == 1
            && let Extension {
                id: IntOrOid::Int(2),
                critical,
                value: ExtensionValue::KeyUsage(v),
            } = &self.0[0]
        {
            let signed = if *critical { -(*v as i32) } else { *v as i32 };
            e.i32(signed)?;
            return Ok(());
        }
        e.array(self.0.len() as u64 * 2)?;
        for ext in &self.0 {
            ext.encode(e)?;
        }
        Ok(())
    }
}
