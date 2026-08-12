//! `AlgorithmIdentifier` (Section 3.1.3 / 3.1.7):
//!
//! ```text
//! AlgorithmIdentifier = int / ~oid /
//!                     [ algorithm: ~oid, parameters: bytes ]
//! ```
//!
//! Used for both `issuerSignatureAlgorithm` (§8.14 registry) and
//! `subjectPublicKeyAlgorithm` (§8.15 registry). The three alternatives are
//! distinguished purely by CBOR major type (int / bytes / array) since `~oid`
//! carries no CBOR tag on the wire (see crate-level notes).

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use oid::ObjectIdentifier;

use crate::common;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmIdentifier {
    /// A registry value from Section 8.14 (signature algorithms) or Section
    /// 8.15 (public key algorithms).
    Int(i32),
    /// An algorithm identified by OID, with DER-encoded parameters carried
    /// verbatim as an opaque byte string when present.
    Oid {
        algorithm: ObjectIdentifier,
        parameters: Option<Vec<u8>>,
    },
}

impl AlgorithmIdentifier {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => {
                let len = crate::common::definite_array_len(d)?;
                if len != 2 {
                    return Err(Error::malformed(
                        "AlgorithmIdentifier array must have exactly 2 elements",
                    ));
                }
                let algorithm = common::decode_oid(d)?;
                let parameters = d.bytes()?.to_vec();
                Ok(AlgorithmIdentifier::Oid {
                    algorithm,
                    parameters: Some(parameters),
                })
            }
            Type::Bytes => Ok(AlgorithmIdentifier::Oid {
                algorithm: common::decode_oid(d)?,
                parameters: None,
            }),
            _ => Ok(AlgorithmIdentifier::Int(d.i32()?)),
        }
    }

    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            AlgorithmIdentifier::Int(n) => {
                e.i32(*n)?;
            }
            AlgorithmIdentifier::Oid {
                algorithm,
                parameters: None,
            } => {
                e.bytes(&common::oid_bytes(algorithm))?;
            }
            AlgorithmIdentifier::Oid {
                algorithm,
                parameters: Some(params),
            } => {
                e.array(2)?;
                e.bytes(&common::oid_bytes(algorithm))?;
                e.bytes(params)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(bytes: &[u8]) -> AlgorithmIdentifier {
        let mut d = Decoder::new(bytes);
        let v = AlgorithmIdentifier::decode(&mut d).unwrap();
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        v.encode(&mut e).unwrap();
        assert_eq!(buf, bytes);
        v
    }

    #[test]
    fn int_form() {
        // 0x00 = int 0 (ECDSA with SHA-256)
        assert_eq!(roundtrip(&[0x00]), AlgorithmIdentifier::Int(0));
    }

    #[test]
    fn oid_form() {
        // bstr(3) 2A 86 48 == rsaEncryption prefix (arbitrary bytes for test)
        let bytes = [0x43, 0x2A, 0x86, 0x48];
        match roundtrip(&bytes) {
            AlgorithmIdentifier::Oid {
                parameters: None, ..
            } => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn oid_with_params_form() {
        // array(2) [ bstr(1) 0x2A, bstr(1) 0x05 ]
        let bytes = [0x82, 0x41, 0x2A, 0x41, 0x05];
        match roundtrip(&bytes) {
            AlgorithmIdentifier::Oid {
                parameters: Some(p),
                ..
            } => assert_eq!(p, vec![0x05]),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
