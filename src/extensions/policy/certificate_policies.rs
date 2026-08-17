//! `CertificatePolicies` (id 6).
//! `CertificatePolicies = [ + ( PolicyIdentifier, [ * PolicyQualifierInfo ] ) ]`

use minicbor::{Decoder, Encoder};

use crate::common::{self, IntOrOid};
use crate::error::{Error, Result};

/// `CertificatePolicies = [ + ( PolicyIdentifier, [ * PolicyQualifierInfo ] ) ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePolicies(pub Vec<(PolicyIdentifier, Vec<PolicyQualifierInfo>)>);

impl CertificatePolicies {
    /// Decode a `CertificatePolicies`. Its `+ ( PolicyIdentifier, [ * PolicyQualifierInfo ] )`
    /// entries are flattened pairs, so the array length is `2 * entries.len()`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let len = common::definite_array_len(d)?;
        if len % 2 != 0 {
            return Err(Error::malformed(
                "CertificatePolicies array must have an even number of elements",
            ));
        }
        let mut out = Vec::with_capacity((len / 2) as usize);
        for _ in 0..(len / 2) {
            let policy_identifier = PolicyIdentifier::decode(d)?;
            let qualifiers = decode_policy_qualifiers(d)?;
            out.push((policy_identifier, qualifiers));
        }
        Ok(Self(out))
    }

    /// Encode a `CertificatePolicies`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.0.len() as u64 * 2)?;
        for (id, qualifiers) in &self.0 {
            id.encode(e)?;
            encode_policy_qualifiers(qualifiers, e)?;
        }
        Ok(())
    }
}

/// `PolicyIdentifier = int / ~oid`.
pub type PolicyIdentifier = IntOrOid;

/// `PolicyQualifierInfo = ( policyQualifierId: int / ~oid, qualifier: text )`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyQualifierInfo {
    /// The policy qualifier identifier.
    pub id: IntOrOid,
    /// The policy qualifier.
    pub qualifier: String,
}

impl PolicyQualifierInfo {
    /// Decode a `PolicyQualifierInfo`.
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let id = IntOrOid::decode(d)?;
        let qualifier = d.str()?.to_string();
        Ok(Self { id, qualifier })
    }

    /// Encode a `PolicyQualifierInfo`.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        self.id.encode(e)?;
        e.str(&self.qualifier)?;
        Ok(())
    }
}

fn decode_policy_qualifiers(d: &mut Decoder<'_>) -> Result<Vec<PolicyQualifierInfo>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed(
            "PolicyQualifierInfo array must have an even number of elements",
        ));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        out.push(PolicyQualifierInfo::decode(d)?);
    }
    Ok(out)
}

fn encode_policy_qualifiers<W: minicbor::encode::Write>(
    v: &[PolicyQualifierInfo],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(v.len() as u64 * 2)?;
    for q in v {
        q.encode(e)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(policies: &CertificatePolicies) -> CertificatePolicies {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        policies.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        CertificatePolicies::decode(&mut d).unwrap()
    }

    #[test]
    fn policy_without_qualifiers_roundtrip() {
        let policies = CertificatePolicies(vec![(IntOrOid::Int(1), vec![])]);
        assert_eq!(roundtrip(&policies), policies);
    }

    #[test]
    fn policy_with_qualifiers_roundtrip() {
        let policies = CertificatePolicies(vec![(
            IntOrOid::Int(1),
            vec![
                PolicyQualifierInfo {
                    id: IntOrOid::Int(1),
                    qualifier: "https://example.com/cps".to_string(),
                },
                PolicyQualifierInfo {
                    id: IntOrOid::Int(2),
                    qualifier: "user notice".to_string(),
                },
            ],
        )]);
        assert_eq!(roundtrip(&policies), policies);
    }

    #[test]
    fn multiple_policies_with_oid_identifier_roundtrip() {
        let policies = CertificatePolicies(vec![
            (IntOrOid::Int(2), vec![]),
            (
                IntOrOid::Oid(oid::ObjectIdentifier::try_from("1.2.3.4.5").unwrap()),
                vec![PolicyQualifierInfo {
                    id: IntOrOid::Oid(
                        oid::ObjectIdentifier::try_from("1.3.6.1.5.5.7.2.1").unwrap(),
                    ),
                    qualifier: "https://example.com/cps".to_string(),
                }],
            ),
        ]);
        assert_eq!(roundtrip(&policies), policies);
    }
}
