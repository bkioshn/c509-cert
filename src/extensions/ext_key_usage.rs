//! `ExtKeyUsageSyntax` (id 8).
//! `ExtKeyUsageSyntax = [ 2* KeyPurposeId ] / KeyPurposeId`

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};

use crate::common::IntOrOid;
use crate::error::Result;

/// `ExtKeyUsageSyntax = [ 2* KeyPurposeId ] / KeyPurposeId`
/// A wrapper around a vector of `KeyPurposeId`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtKeyUsage(pub Vec<IntOrOid>);

impl ExtKeyUsage {
    /// Decode an `ExtKeyUsage`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => Ok(ExtKeyUsage(d.decode()?)),
            _ => Ok(ExtKeyUsage(vec![IntOrOid::decode(d)?])),
        }
    }

    /// Encode an `ExtKeyUsage`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        if let [single] = self.0.as_slice() {
            single.encode(e)?;
            return Ok(());
        }
        e.array(self.0.len() as u64)?;
        for item in &self.0 {
            item.encode(e)?;
        }
        Ok(())
    }
}
