//! ```text
//! Name = [ * RDNAttribute ] / SpecialText
//! ```

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use oid::ObjectIdentifier;

use crate::common::{self, SpecialText};
use crate::error::{Error, Result};

/// Registry id for `commonName` (Section 8.6, value 1), used by the compact
/// single-attribute `Name` shortcut.
const COMMON_NAME_ID: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdnAttribute {
    /// RDNAttribute = ( attributeType: int, attributeValue: [ + SpecialText] )
    /// ID is positive for utf8String, negative for printableString
    Registered {
        /// The attribute type.
        id: u16,
        /// Whether the attribute value is a printable string.
        printable_string: bool,
        /// The attribute value.
        value: SpecialText,
    },
    /// RDNAttributes = ( attributeType: ~oid, attributeValue: [+ bytes] )
    Oid {
        /// The attribute type.
        oid: ObjectIdentifier,
        /// The attribute value.
        value: Vec<u8>,
    },
}

/// A name containing a sequence of RDNAttributes or a single SpecialText.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Name(pub Vec<RdnAttribute>);

impl Name {
    /// Decode a `Name` from a CBOR data item.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => {
                let len = crate::common::definite_array_len(d)?;
                if len % 2 != 0 {
                    return Err(Error::malformed(
                        "Name array must have an even number of elements",
                    ));
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

    /// Decode a `RdnAttribute` from a CBOR data item.
    fn decode_attribute(d: &mut Decoder<'_>) -> Result<RdnAttribute> {
        match d.datatype()? {
            Type::Bytes => {
                let oid = common::decode_oid(d)?;
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

    /// Encode a `Name` as a CBOR data item.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        if let [
            RdnAttribute::Registered {
                id: COMMON_NAME_ID,
                printable_string: false,
                value,
            },
        ] = self.0.as_slice()
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
                    let raw = if *printable_string {
                        -(*id as i32)
                    } else {
                        *id as i32
                    };
                    e.i32(raw)?;
                    value.encode(e)?;
                }
                RdnAttribute::Oid { oid, value } => {
                    e.bytes(&common::oid_bytes(oid))?;
                    e.bytes(value)?;
                }
            }
        }
        Ok(())
    }

    /// Encode a `Name` or `null` as a CBOR data item.
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
        let name = Name(vec![RdnAttribute::Registered {
            id: 1,
            printable_string: false,
            value: SpecialText::Text("RFC test CA".to_string()),
        }]);
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        name.encode(&mut e).unwrap();

        let mut d = Decoder::new(&buf);
        let decoded = Name::decode(&mut d).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn multi_attribute_roundtrip() {
        let name = Name(vec![
            RdnAttribute::Registered {
                id: 1,
                printable_string: false,
                value: SpecialText::Text("cn".to_string()),
            },
            RdnAttribute::Registered {
                id: 4,
                printable_string: false,
                value: SpecialText::Text("us".to_string()),
            },
        ]);
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        name.encode(&mut e).unwrap();

        let mut d = Decoder::new(&buf);
        let decoded = Name::decode(&mut d).unwrap();
        assert_eq!(decoded, name);
    }
}
