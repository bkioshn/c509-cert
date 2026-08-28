//! `NameConstraints` (id 26).
//! `NameConstraints = [ permittedSubtrees: GeneralSubtrees / null,
//!                     excludedSubtrees: GeneralSubtrees / null ]`

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};

use super::general_name::{GeneralName, decode_general_names, encode_general_names};
use crate::common;
use crate::error::Result;

/// An `NameConstraints` extension.
/// `NameConstraints = [ permittedSubtrees: GeneralSubtrees / null,
///                     excludedSubtrees: GeneralSubtrees / null ]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameConstraints {
    pub permitted: Option<Vec<GeneralName>>,
    pub excluded: Option<Vec<GeneralName>>,
}

impl NameConstraints {
    /// Decode a `NameConstraints`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        common::expect_array_len(d, 2)?;
        let permitted = decode_opt_general_subtree(d)?;
        let excluded = decode_opt_general_subtree(d)?;
        Ok(NameConstraints {
            permitted,
            excluded,
        })
    }

    /// Encode a `NameConstraints`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;
        encode_opt_general_subtree(&self.permitted, e)?;
        encode_opt_general_subtree(&self.excluded, e)?;
        Ok(())
    }
}

/// Decode an optional `GeneralSubtree`.
fn decode_opt_general_subtree(d: &mut Decoder<'_>) -> Result<Option<Vec<GeneralName>>> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        Ok(Some(decode_general_names(d)?))
    }
}

/// Encode an optional `GeneralSubtree`.
fn encode_opt_general_subtree<W: minicbor::encode::Write>(
    v: &Option<Vec<GeneralName>>,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match v {
        Some(names) => encode_general_names(names, e)?,
        None => {
            e.null()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::general_name::GeneralNameValue;

    fn roundtrip(nc: &NameConstraints) -> NameConstraints {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        nc.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        NameConstraints::decode(&mut d).unwrap()
    }

    #[test]
    fn both_subtrees_present_roundtrip() {
        let nc = NameConstraints {
            permitted: Some(vec![GeneralName {
                kind: 2,
                value: GeneralNameValue::DnsName("example.com".to_string()),
            }]),
            excluded: Some(vec![GeneralName {
                kind: 2,
                value: GeneralNameValue::DnsName("bad.example.com".to_string()),
            }]),
        };
        assert_eq!(roundtrip(&nc), nc);
    }

    #[test]
    fn both_subtrees_null_roundtrip() {
        let nc = NameConstraints {
            permitted: None,
            excluded: None,
        };
        assert_eq!(roundtrip(&nc), nc);
    }

    #[test]
    fn mixed_null_and_present_roundtrip() {
        let nc = NameConstraints {
            permitted: Some(vec![GeneralName {
                kind: 2,
                value: GeneralNameValue::DnsName("example.com".to_string()),
            }]),
            excluded: None,
        };
        assert_eq!(roundtrip(&nc), nc);
    }
}
