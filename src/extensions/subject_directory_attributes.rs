//! `SubjectDirectoryAttributes` (id 24).
//! `SubjectDirectoryAttributes = [ + RDNAttributes ]`

use minicbor::{Decoder, Encoder};
use oid::ObjectIdentifier;

use crate::common::{self, SpecialText};
use crate::error::{Error, Result};

/// `SubjectDirectoryAttributes = [ + RDNAttributes ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDirectoryAttributes(pub Vec<RDNAttributes>);

impl SubjectDirectoryAttributes {
    /// Decode a `SubjectDirectoryAttributes`. Its `+ RDNAttributes` entries are
    /// flattened `(attributeType, attributeValue)` pairs, so the array length
    /// is `2 * entries.len()`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = common::definite_array_len(d)?;
        if len % 2 != 0 {
            return Err(Error::malformed(
                "SubjectDirectoryAttributes array must have an even number of elements",
            ));
        }
        let mut out = Vec::with_capacity((len / 2) as usize);
        for _ in 0..(len / 2) {
            out.push(RDNAttributes::decode(d)?);
        }
        Ok(Self(out))
    }

    /// Encode a `SubjectDirectoryAttributes`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.0.len() as u64 * 2)?;
        for attr in &self.0 {
            attr.encode(e)?;
        }
        Ok(())
    }
}

/// `RDNAttributes = (
///     ( attributeType: int, attributeValue: [ + SpecialText] ) //
///     ( attributeType: ~oid, attributeValue: [+ bytes] )
///   )`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RDNAttributes {
    /// `attributeType: int, attributeValue: [ + SpecialText ]`.
    Registered {
        /// The attribute type.
        id: u16,
        /// Whether the attribute value is a printable string.
        printable_string: bool,
        /// The attribute values.
        values: Vec<SpecialText>,
    },
    /// `attributeType: ~oid, attributeValue: [ + bytes ]`.
    Oid {
        /// The attribute type.
        oid: ObjectIdentifier,
        /// The attribute values.
        values: Vec<Vec<u8>>,
    },
}

impl RDNAttributes {
    /// Decode a single `RDNAttributes` entry.
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match common::RdnAttributeType::decode(d)? {
            common::RdnAttributeType::Oid(oid) => {
                let n = common::definite_array_len(d)?;
                let mut values = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    values.push(d.bytes()?.to_vec());
                }
                Ok(RDNAttributes::Oid { oid, values })
            }
            common::RdnAttributeType::Registered {
                id,
                printable_string,
            } => {
                let n = common::definite_array_len(d)?;
                let mut values = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    values.push(SpecialText::decode(d)?);
                }
                Ok(RDNAttributes::Registered {
                    id,
                    printable_string,
                    values,
                })
            }
        }
    }

    /// Encode a single `RDNAttributes` entry.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            RDNAttributes::Registered {
                id,
                printable_string,
                values,
            } => {
                common::RdnAttributeType::Registered {
                    id: *id,
                    printable_string: *printable_string,
                }
                .encode(e)?;
                e.array(values.len() as u64)?;
                for val in values {
                    val.encode(e)?;
                }
            }
            RDNAttributes::Oid { oid, values } => {
                common::RdnAttributeType::Oid(oid.clone()).encode(e)?;
                e.array(values.len() as u64)?;
                for val in values {
                    e.bytes(val)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(attrs: &SubjectDirectoryAttributes) -> SubjectDirectoryAttributes {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        attrs.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        SubjectDirectoryAttributes::decode(&mut d).unwrap()
    }

    #[test]
    fn registered_utf8_attribute_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![RDNAttributes::Registered {
            id: 3,
            printable_string: false,
            values: vec![SpecialText::Text("example".to_string())],
        }]);
        assert_eq!(roundtrip(&attrs), attrs);
    }

    #[test]
    fn registered_printable_string_attribute_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![RDNAttributes::Registered {
            id: 3,
            printable_string: true,
            values: vec![
                SpecialText::Text("US".to_string()),
                SpecialText::Text("CA".to_string()),
            ],
        }]);
        assert_eq!(roundtrip(&attrs), attrs);
    }

    #[test]
    fn oid_attribute_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![RDNAttributes::Oid {
            oid: ObjectIdentifier::try_from("1.2.3.4.5").unwrap(),
            values: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        }]);
        assert_eq!(roundtrip(&attrs), attrs);
    }

    #[test]
    fn multiple_attributes_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![
            RDNAttributes::Registered {
                id: 3,
                printable_string: false,
                values: vec![SpecialText::Text("example".to_string())],
            },
            RDNAttributes::Oid {
                oid: ObjectIdentifier::try_from("1.2.3.4.5").unwrap(),
                values: vec![vec![1, 2, 3]],
            },
        ]);
        assert_eq!(roundtrip(&attrs), attrs);
    }
}
