//! `Name` / `RDNAttribute` (Section 3.1.4/3.1.6):
//!
//! ```text
//! Name = [ * RDNAttribute ] / SpecialText
//!
//! RDNAttribute = (
//!     ( attributeType: int, attributeValue: SpecialText ) //
//!     ( attributeType: ~oid, attributeValue: bytes )
//! )
//! ```
//!
//! `issuer`/`subject` RDNSequences with more than one AttributeTypeAndValue
//! per RDN are not supported by C509 (the draft explicitly excludes multi-
//! valued RDNs from this grammar), so each `RdnAttribute` is one (type,
//! value) pair.

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::common::SpecialText;
use crate::error::{Error, Result};
use crate::oid::Oid;

/// Registry id for `commonName` (Section 8.6, value 1), used by the compact
/// single-attribute `Name` shortcut.
const COMMON_NAME_ID: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdnAttribute {
    /// `attributeType` was encoded as a CBOR int: `id` is `abs(value)`
    /// (looked up via [`crate::registry::rdn_attribute_name`]),
    /// `printable_string` is `true` when the int was negative
    /// (X.520 `PrintableString`) and `false` when positive (`utf8String` or,
    /// for IA5String-only attributes, unambiguously non-negative).
    Registered {
        id: u16,
        printable_string: bool,
        value: SpecialText,
    },
    /// `attributeType` was encoded as `~oid` (no registry entry available).
    Oid { oid: Oid, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Name(pub Vec<RdnAttribute>);

impl Name {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => {
                let len = crate::common::definite_array_len(d)?;
                if len % 2 != 0 {
                    return Err(Error::malformed("Name array must have an even number of elements"));
                }
                let mut attrs = Vec::with_capacity((len / 2) as usize);
                for _ in 0..(len / 2) {
                    attrs.push(Self::decode_attribute(d)?);
                }
                Ok(Name(attrs))
            }
            // Compact form: Name contains a single commonName attribute,
            // encoded as just the bare SpecialText (attributeType == +1).
            _ => {
                let value = SpecialText::decode(d)?;
                Ok(Name(vec![RdnAttribute::Registered {
                    id: COMMON_NAME_ID,
                    printable_string: false,
                    value,
                }]))
            }
        }
    }

    fn decode_attribute(d: &mut Decoder<'_>) -> Result<RdnAttribute> {
        match d.datatype()? {
            Type::Bytes => {
                let oid = Oid::new(d.bytes()?.to_vec());
                let value = d.bytes()?.to_vec();
                Ok(RdnAttribute::Oid { oid, value })
            }
            _ => {
                let raw = d.i32()?;
                let printable_string = raw < 0;
                let id = raw.unsigned_abs() as u16;
                let value = SpecialText::decode(d)?;
                Ok(RdnAttribute::Registered {
                    id,
                    printable_string,
                    value,
                })
            }
        }
    }

    /// Decode the `Name / null` alternation used for `issuer` (`null` means
    /// "identical to `subject`", i.e. a self-signed certificate).
    pub(crate) fn decode_optional(d: &mut Decoder<'_>) -> Result<Option<Name>> {
        if d.datatype()? == Type::Null {
            d.null()?;
            return Ok(None);
        }
        Ok(Some(Name::decode(d)?))
    }

    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        if let [RdnAttribute::Registered {
            id: COMMON_NAME_ID,
            printable_string: false,
            value,
        }] = self.0.as_slice()
        {
            value.encode(e)?;
            return Ok(());
        }
        e.array(self.0.len() as u64 * 2)?;
        for attr in &self.0 {
            match attr {
                RdnAttribute::Registered {
                    id,
                    printable_string,
                    value,
                } => {
                    let raw = if *printable_string { -(*id as i32) } else { *id as i32 };
                    e.i32(raw)?;
                    value.encode(e)?;
                }
                RdnAttribute::Oid { oid, value } => {
                    e.bytes(oid.as_bytes())?;
                    e.bytes(value)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encode_optional<W: minicbor::encode::Write>(
        value: &Option<Name>,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match value {
            None => {
                e.null()?;
            }
            Some(name) => name.encode(e)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_common_name_roundtrip() {
        // text(11) "RFC test CA"
        let bytes = b"\x6bRFC test CA";
        let mut d = Decoder::new(bytes);
        let name = Name::decode(&mut d).unwrap();
        assert_eq!(
            name.0,
            vec![RdnAttribute::Registered {
                id: 1,
                printable_string: false,
                value: SpecialText::Text("RFC test CA".to_string()),
            }]
        );
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        name.encode(&mut e).unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn multi_attribute_roundtrip() {
        // [ 1, "cn", 4, "us" ]  -> array(4) text(2) "cn" int(4) text(2) "us"
        let bytes = [0x84, 0x01, 0x62, b'c', b'n', 0x04, 0x62, b'u', b's'];
        let mut d = Decoder::new(&bytes);
        let name = Name::decode(&mut d).unwrap();
        assert_eq!(name.0.len(), 2);
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        name.encode(&mut e).unwrap();
        assert_eq!(buf, bytes);
    }
}
