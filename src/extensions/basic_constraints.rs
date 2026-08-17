//! `BasicConstraints` (Section 3.3, extension registry value 4).
//! If 'cA' = false then extensionValue = -2,
//! If 'cA' = true and 'pathLenConstraint' is not present then extensionValue = -1,
//! If 'cA' = true and 'pathLenConstraint' is present then extensionValue = pathLenConstraint.

use minicbor::{Decoder, Encoder};

use crate::error::{Error, Result};

/// A `BasicConstraints`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasicConstraints {
    /// The certificate is not a CA certificate.
    NotCa,
    /// The certificate is a CA certificate.
    Ca { path_len: Option<u32> },
}

impl BasicConstraints {
    /// Decode a `BasicConstraints`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let v = d.i32()?;
        match v {
            -2 => Ok(BasicConstraints::NotCa),
            -1 => Ok(BasicConstraints::Ca { path_len: None }),
            n if n >= 0 => Ok(BasicConstraints::Ca {
                path_len: Some(n as u32),
            }),
            _ => Err(Error::malformed("invalid basicConstraints value")),
        }
    }

    /// Encode a `BasicConstraints`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            BasicConstraints::NotCa => {
                e.i32(-2)?;
            }
            BasicConstraints::Ca { path_len: None } => {
                e.i32(-1)?;
            }
            BasicConstraints::Ca { path_len: Some(n) } => {
                e.i32(*n as i32)?;
            }
        }
        Ok(())
    }
}
