//! `PolicyMappings` (id 27).
//! `PolicyMappings` = [
//!     + (issuerDomainPolicy: int/~oid, subjectDomainPolicy: int/~oid)
//!   ]

use minicbor::{Decoder, Encoder};

use crate::common::{self, IntOrOid};
use crate::error::{Error, Result};

/// `PolicyMappings = [ + (issuerDomainPolicy: int/~oid, subjectDomainPolicy: int/~oid) ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMappings(pub Vec<(IntOrOid, IntOrOid)>);

impl PolicyMappings {
    /// Decode a `PolicyMappings`. Its `+ (issuerDomainPolicy, subjectDomainPolicy)`
    /// entries are flattened pairs, so the array length is `2 * entries.len()`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = common::definite_array_len(d)?;
        if len % 2 != 0 {
            return Err(Error::malformed(
                "PolicyMappings array must have an even number of elements",
            ));
        }
        let mut out = Vec::with_capacity((len / 2) as usize);
        for _ in 0..(len / 2) {
            let issuer_domain_policy = IntOrOid::decode(d)?;
            let subject_domain_policy = IntOrOid::decode(d)?;
            out.push((issuer_domain_policy, subject_domain_policy));
        }
        Ok(Self(out))
    }

    /// Encode a `PolicyMappings`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.0.len() as u64 * 2)?;
        for (a, b) in &self.0 {
            a.encode(e)?;
            b.encode(e)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(mappings: &PolicyMappings) -> PolicyMappings {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        mappings.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        PolicyMappings::decode(&mut d).unwrap()
    }

    #[test]
    fn single_mapping_roundtrip() {
        let mappings = PolicyMappings(vec![(IntOrOid::Int(1), IntOrOid::Int(2))]);
        assert_eq!(roundtrip(&mappings), mappings);
    }

    #[test]
    fn multiple_mappings_with_oid_roundtrip() {
        let mappings = PolicyMappings(vec![
            (IntOrOid::Int(1), IntOrOid::Int(2)),
            (
                IntOrOid::Oid(oid::ObjectIdentifier::try_from("1.2.3.4.5").unwrap()),
                IntOrOid::Oid(oid::ObjectIdentifier::try_from("1.2.3.4.6").unwrap()),
            ),
        ]);
        assert_eq!(roundtrip(&mappings), mappings);
    }
}
