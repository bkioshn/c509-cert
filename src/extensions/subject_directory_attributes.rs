//! `SubjectDirectoryAttributes` (id 24).
//! `SubjectDirectoryAttributes = [ + RDNAttributes ]`

use minicbor::{Decoder, Encoder};

use crate::common::{self, RdnAttr, SpecialText};
use crate::error::{Error, Result};

/// `RDNAttributes = ( attributeType: int, attributeValue: [ + SpecialText] ) //
///                  ( attributeType: ~oid, attributeValue: [+ bytes] )`
pub type RdnAttributes = RdnAttr<Vec<SpecialText>, Vec<Vec<u8>>>;

/// `SubjectDirectoryAttributes = [ + RDNAttributes ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDirectoryAttributes(pub Vec<RdnAttributes>);

impl SubjectDirectoryAttributes {
    /// Decode a `SubjectDirectoryAttributes`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = common::definite_array_len(d)?;
        if len % 2 != 0 {
            return Err(Error::malformed(
                "SubjectDirectoryAttributes array must have an even number of elements",
            ));
        }
        let mut out = Vec::with_capacity((len / 2) as usize);
        for _ in 0..(len / 2) {
            out.push(RdnAttributes::decode(d)?);
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
        let attrs = SubjectDirectoryAttributes(vec![RdnAttributes::Registered {
            id: 3,
            printable_string: false,
            value: vec![SpecialText::Text("example".to_string())],
        }]);
        assert_eq!(roundtrip(&attrs), attrs);
    }

    #[test]
    fn registered_printable_string_attribute_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![RdnAttributes::Registered {
            id: 3,
            printable_string: true,
            value: vec![
                SpecialText::Text("US".to_string()),
                SpecialText::Text("CA".to_string()),
            ],
        }]);
        assert_eq!(roundtrip(&attrs), attrs);
    }

    #[test]
    fn oid_attribute_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![RdnAttributes::Oid {
            oid: oid::ObjectIdentifier::try_from("1.2.3.4.5").unwrap(),
            value: vec![vec![0xde, 0xad, 0xbe, 0xef]],
        }]);
        assert_eq!(roundtrip(&attrs), attrs);
    }

    #[test]
    fn multiple_attributes_roundtrip() {
        let attrs = SubjectDirectoryAttributes(vec![
            RdnAttributes::Registered {
                id: 3,
                printable_string: false,
                value: vec![SpecialText::Text("example".to_string())],
            },
            RdnAttributes::Oid {
                oid: oid::ObjectIdentifier::try_from("1.2.3.4.5").unwrap(),
                value: vec![vec![1, 2, 3]],
            },
        ]);
        assert_eq!(roundtrip(&attrs), attrs);
    }
}
