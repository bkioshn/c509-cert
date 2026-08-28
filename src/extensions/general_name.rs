//! `GeneralName` (Section 8.13 "C509 General Names Registry"), used by
//! `SubjectAltName`/`IssuerAltName`, `AuthorityKeyIdentifier`, and
//! `NameConstraints`.

use macaddr::MacAddr;
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};
use strum::{EnumDiscriminants, FromRepr};

use crate::common;
use crate::error::{Error, Result};
use crate::name::Name;
use crate::serde_util;

/// Section 8.13 "C509 General Names Registry".
///
/// Each variant's discriminant is its registry value; `GeneralNameKind`
#[derive(Debug, Clone, PartialEq, Eq, EnumDiscriminants, Serialize, Deserialize)]
#[strum_discriminants(name(GeneralNameKind), derive(FromRepr))]
#[repr(i32)]
pub enum GeneralNameValue {
    /// `otherName` (registry value 0): `[ ~oid, bytes ]`.
    OtherName {
        #[serde(with = "serde_util::oid_str")]
        type_id: ObjectIdentifier,
        #[serde(with = "serde_util::hex_bytes")]
        value: Vec<u8>,
    } = 0,
    /// `otherName` with `id-on-hardwareModuleName` (registry value -1).
    HardwareModuleName {
        #[serde(with = "serde_util::oid_str")]
        hw_type: ObjectIdentifier,
        #[serde(with = "serde_util::hex_bytes")]
        hw_serial_num: Vec<u8>,
    } = -1,
    /// `otherName` with `id-on-SmtpUTF8Mailbox` (registry value -2).
    SmtpUtf8Mailbox(String) = -2,
    /// `otherName` with `id-on-MACAddress` (registry value -3).
    MacAddress(#[serde(with = "serde_util::display_str")] MacAddr) = -3,
    Rfc822Name(String) = 1,
    DnsName(String) = 2,
    DirectoryName(Name) = 4,
    Uri(String) = 6,
    IpAddress(#[serde(with = "serde_util::hex_bytes")] Vec<u8>) = 7,
    RegisteredId(#[serde(with = "serde_util::oid_str")] ObjectIdentifier) = 8,
    /// A `GeneralNameType` this crate does not decode; the raw CBOR item.
    ///
    /// Not a real registry value; the discriminant is a sentinel that never
    /// collides with a registry entry so it always falls into the same
    /// catch-all arm as `None` in `GeneralName::decode`.
    Raw(#[serde(with = "serde_util::hex_bytes")] Vec<u8>) = i32::MIN,
}

/// A `GeneralName` is a single name in a list of names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralName {
    pub kind: i32,
    pub value: GeneralNameValue,
}

impl GeneralName {
    /// Decode a `GeneralName`.
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let kind = d.i32()?;
        let value = match GeneralNameKind::from_repr(kind) {
            Some(GeneralNameKind::MacAddress) => {
                GeneralNameValue::MacAddress(common::decode_mac(d.bytes()?)?)
            }
            Some(GeneralNameKind::SmtpUtf8Mailbox) => {
                GeneralNameValue::SmtpUtf8Mailbox(d.str()?.to_string())
            }
            Some(GeneralNameKind::HardwareModuleName) => {
                common::expect_array_len(d, 2)?;
                let hw_type = common::decode_oid(d)?;
                let hw_serial_num = d.bytes()?.to_vec();
                GeneralNameValue::HardwareModuleName {
                    hw_type,
                    hw_serial_num,
                }
            }
            Some(GeneralNameKind::OtherName) => {
                common::expect_array_len(d, 2)?;
                let type_id = common::decode_oid(d)?;
                let value = d.bytes()?.to_vec();
                GeneralNameValue::OtherName { type_id, value }
            }
            Some(GeneralNameKind::Rfc822Name) => GeneralNameValue::Rfc822Name(d.str()?.to_string()),
            Some(GeneralNameKind::DnsName) => GeneralNameValue::DnsName(d.str()?.to_string()),
            Some(GeneralNameKind::DirectoryName) => {
                GeneralNameValue::DirectoryName(Name::decode(d)?)
            }
            Some(GeneralNameKind::Uri) => GeneralNameValue::Uri(d.str()?.to_string()),
            Some(GeneralNameKind::IpAddress) => GeneralNameValue::IpAddress(d.bytes()?.to_vec()),
            Some(GeneralNameKind::RegisteredId) => {
                GeneralNameValue::RegisteredId(common::decode_oid(d)?)
            }
            Some(GeneralNameKind::Raw) | None => GeneralNameValue::Raw(common::raw_item(d)?),
        };
        Ok(GeneralName { kind, value })
    }

    /// Encode a `GeneralName`.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.i32(self.kind)?;
        match &self.value {
            GeneralNameValue::MacAddress(mac) => {
                e.bytes(mac.as_bytes())?;
            }
            GeneralNameValue::SmtpUtf8Mailbox(s) => {
                e.str(s)?;
            }
            GeneralNameValue::HardwareModuleName {
                hw_type,
                hw_serial_num,
            } => {
                e.array(2)?;
                e.bytes(&common::oid_bytes(hw_type))?;
                e.bytes(hw_serial_num)?;
            }
            GeneralNameValue::OtherName { type_id, value } => {
                e.array(2)?;
                e.bytes(&common::oid_bytes(type_id))?;
                e.bytes(value)?;
            }
            GeneralNameValue::Rfc822Name(s)
            | GeneralNameValue::DnsName(s)
            | GeneralNameValue::Uri(s) => {
                e.str(s)?;
            }
            GeneralNameValue::DirectoryName(n) => {
                n.encode(e)?;
            }
            GeneralNameValue::IpAddress(b) => {
                e.bytes(b)?;
            }
            GeneralNameValue::RegisteredId(oid) => {
                e.bytes(&common::oid_bytes(oid))?;
            }
            GeneralNameValue::Raw(bytes) => {
                common::write_raw(e, bytes)?;
            }
        }
        Ok(())
    }
}

/// Decode a list of `GeneralName`s.
pub(crate) fn decode_general_names(d: &mut Decoder<'_>) -> Result<Vec<GeneralName>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed(
            "GeneralNames array must have an even number of elements",
        ));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        out.push(GeneralName::decode(d)?);
    }
    Ok(out)
}

/// Encode a list of `GeneralName`s.
pub(crate) fn encode_general_names<W: minicbor::encode::Write>(
    names: &[GeneralName],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(names.len() as u64 * 2)?;
    for n in names {
        n.encode(e)?;
    }
    Ok(())
}

/// Decode a `SubjectAltName` or `IssuerAltName`.
/// `SubjectAltName = GeneralNames / text` (and identically `IssuerAltName`)
pub(crate) fn decode_alt_name(d: &mut Decoder<'_>) -> Result<Vec<GeneralName>> {
    match d.datatype()? {
        Type::String => {
            let s = d.str()?.to_string();
            Ok(vec![GeneralName {
                kind: 2,
                value: GeneralNameValue::DnsName(s),
            }])
        }
        _ => decode_general_names(d),
    }
}

/// Encode a `SubjectAltName` or `IssuerAltName`.
pub(crate) fn encode_alt_name<W: minicbor::encode::Write>(
    names: &[GeneralName],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    if names.len() == 1
        && let GeneralName {
            kind: 2,
            value: GeneralNameValue::DnsName(s),
        } = &names[0]
    {
        e.str(s)?;
        return Ok(());
    }
    encode_general_names(names, e)
}
