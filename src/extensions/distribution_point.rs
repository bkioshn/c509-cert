//! `DistributionPointName`, shared by `CRLDistributionPoints` (id 5) and
//! `FreshestCRL` (id 29).
//!  DistributionPointName = [
//!     fullName:  [ 2 * text ] / text,
//!     reasons:   uint / null,
//!     cRLIssuer: Name / null,
//! ]

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};

use crate::common;
use crate::error::Result;
use crate::name::Name;

/// A `DistributionPointName`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionPointName {
    /// The full name of the distribution point.
    pub full_name: Vec<String>,
    /// The reasons for the distribution point.
    pub reasons: Option<u32>,
    /// The CRL issuer.
    pub crl_issuer: Option<Name>,
}

impl DistributionPointName {
    /// Decode a `DistributionPointName`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Vec<Self>> {
        match d.datatype()? {
            Type::String => {
                let s = d.str()?.to_string();
                Ok(vec![DistributionPointName {
                    full_name: vec![s],
                    reasons: None,
                    crl_issuer: None,
                }])
            }
            _ => {
                let len = common::definite_array_len(d)?;
                let mut out = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    common::expect_array_len(d, 3)?;
                    let full_name = match d.datatype()? {
                        Type::String => vec![d.str()?.to_string()],
                        _ => {
                            let n = common::definite_array_len(d)?;
                            let mut v = Vec::with_capacity(n as usize);
                            for _ in 0..n {
                                v.push(d.str()?.to_string());
                            }
                            v
                        }
                    };
                    let reasons = common::decode_opt_uint(d)?;
                    let crl_issuer = Name::decode_optional(d)?;
                    out.push(DistributionPointName {
                        full_name,
                        reasons,
                        crl_issuer,
                    });
                }
                Ok(out)
            }
        }
    }

    /// Encode a `DistributionPointName`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        points: &[DistributionPointName],
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        if points.len() == 1 {
            let dp = &points[0];
            if dp.full_name.len() == 1 && dp.reasons.is_none() && dp.crl_issuer.is_none() {
                e.str(&dp.full_name[0])?;
                return Ok(());
            }
        }
        e.array(points.len() as u64)?;
        for dp in points {
            e.array(3)?;
            match dp.full_name.as_slice() {
                [single] => {
                    e.str(single)?;
                }
                many => {
                    e.array(many.len() as u64)?;
                    for s in many {
                        e.str(s)?;
                    }
                }
            }
            common::encode_opt_uint(e, dp.reasons)?;
            Name::encode_optional(&dp.crl_issuer, e)?;
        }
        Ok(())
    }
}
