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
                let n = i32::try_from(*n).map_err(|_| {
                    minicbor::encode::Error::message(
                        "pathLenConstraint too large to encode as a signed CBOR int",
                    )
                })?;
                e.i32(n)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: &BasicConstraints) -> BasicConstraints {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        value.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        BasicConstraints::decode(&mut d).unwrap()
    }

    #[test]
    fn not_ca_roundtrip() {
        let value = BasicConstraints::NotCa;
        assert_eq!(roundtrip(&value), value);
    }

    #[test]
    fn ca_without_path_len_roundtrip() {
        let value = BasicConstraints::Ca { path_len: None };
        assert_eq!(roundtrip(&value), value);
    }

    #[test]
    fn ca_with_path_len_roundtrip() {
        let value = BasicConstraints::Ca { path_len: Some(3) };
        assert_eq!(roundtrip(&value), value);
    }

    #[test]
    fn ca_path_len_too_large_is_rejected() {
        // u32::MAX - 1 would previously wrap through `as i32` into -2, the
        // NotCa sentinel, silently turning a CA cert into a non-CA one.
        let value = BasicConstraints::Ca {
            path_len: Some(u32::MAX - 1),
        };
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        assert!(value.encode(&mut e).is_err());
    }
}
