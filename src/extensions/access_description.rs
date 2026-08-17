//! `AccessDescription`, shared by `AuthorityInfoAccess` (id 9) and
//! `SubjectInfoAccess` (id 31).
/// `AccessDescription = ( accessMethod: int / ~oid , uri: text )`
use minicbor::{Decoder, Encoder};

use crate::common::{self, IntOrOid};
use crate::error::{Error, Result};

/// An `AccessDescription`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDescription {
    /// The access method, either an integer or an OID.
    pub access_method: IntOrOid,
    /// The URI of the access description.
    pub uri: String,
}

impl AccessDescription {
    /// Decode `AccessDescription`s.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Vec<Self>> {
        let len = common::definite_array_len(d)?;
        if len % 2 != 0 {
            return Err(Error::malformed(
                "AccessDescription array must have an even number of elements",
            ));
        }
        let mut out = Vec::with_capacity((len / 2) as usize);
        for _ in 0..(len / 2) {
            let access_method = IntOrOid::decode(d)?;
            let uri = d.str()?.to_string();
            out.push(AccessDescription { access_method, uri });
        }
        Ok(out)
    }

    /// Encode`AccessDescription`s.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        v: &[AccessDescription],
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(v.len() as u64 * 2)?;
        for ad in v {
            ad.access_method.encode(e)?;
            e.str(&ad.uri)?;
        }
        Ok(())
    }
}
