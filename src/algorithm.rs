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
use serde::{Deserialize, Serialize};

use crate::common;
use crate::error::{Error, Result};
use crate::serde_util;

/// An algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmIdentifier {
    /// A registry value from Section 8.14 (signature algorithms) or Section
    /// 8.15 (public key algorithms).
    Int(i32),
    /// An algorithm identified by OID, with DER-encoded parameters carried
    /// verbatim as an opaque byte string when present.
    Oid {
        #[serde(with = "serde_util::oid_str")]
        algorithm: ObjectIdentifier,
        #[serde(
            serialize_with = "serde_util::hex_bytes::serialize_opt",
            deserialize_with = "serde_util::hex_bytes::deserialize_opt"
        )]
        parameters: Option<Vec<u8>>,
    },
}

impl AlgorithmIdentifier {
    /// Decode an `AlgorithmIdentifier`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            // [ algorithm: ~oid, parameters: bytes ]
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
            // ~oid
            Type::Bytes => Ok(AlgorithmIdentifier::Oid {
                algorithm: common::decode_oid(d)?,
                parameters: None,
            }),
            // int
            _ => Ok(AlgorithmIdentifier::Int(d.i32()?)),
        }
    }

    /// Encode an `AlgorithmIdentifier`.
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

    /// rsaEncryption
    const RSA_OID: &str = "1.2.840.113549.1.1.1";
    /// rsaEncryption, DER content octets 2A 86 48 86 F7 0D 01 01 01
    const RSA_OID_DER: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    // Roundtrip the AlgorithmIdentifier through the CBOR encoder and decoder.
    fn roundtrip(algorithm: AlgorithmIdentifier) -> AlgorithmIdentifier {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        algorithm.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        AlgorithmIdentifier::decode(&mut d).unwrap()
    }

    #[test]
    fn int_form() {
        assert_eq!(
            roundtrip(AlgorithmIdentifier::Int(0)),
            AlgorithmIdentifier::Int(0)
        );
    }

    #[test]
    fn int_form_negative() {
        assert_eq!(
            roundtrip(AlgorithmIdentifier::Int(-7)),
            AlgorithmIdentifier::Int(-7)
        );
    }

    #[test]
    fn oid_form() {
        // rsaEncryption, DER content octets 2A 86 48 86 F7 0D 01 01 01
        // wrapped as a 9-byte CBOR bytestring: header 0x49 (major type 2,
        // length 9) followed by the content octets.
        let oid = ObjectIdentifier::try_from(RSA_OID).expect("valid OID");
        let value = AlgorithmIdentifier::Oid {
            algorithm: oid,
            parameters: None,
        };

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        value.encode(&mut e).unwrap();
        let mut expected = vec![0x49]; // bstr header: major type 2, length 9
        expected.extend_from_slice(&RSA_OID_DER);
        assert_eq!(buf, expected);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn oid_with_params_form() {
        // [ ~oid, bytes ]: array(2) header 0x82, the same 10-byte OID
        // bytestring as `oid_form`, then a 1-byte params bytestring.
        let oid = ObjectIdentifier::try_from(RSA_OID).expect("valid OID");
        let value = AlgorithmIdentifier::Oid {
            algorithm: oid,
            parameters: Some(vec![1]),
        };

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        value.encode(&mut e).unwrap();
        let mut expected = vec![0x82, 0x49]; // array(2), bstr(9)
        expected.extend_from_slice(&RSA_OID_DER);
        expected.extend_from_slice(&[0x41, 0x01]); // bstr(1): params = [0x01]
        assert_eq!(buf, expected);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn array_wrong_length_is_malformed() {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.array(3).unwrap();
        e.bytes(&[0x2A]).unwrap();
        e.bytes(&[0x01]).unwrap();
        e.bytes(&[0x02]).unwrap();

        let mut d = Decoder::new(&buf);
        assert!(AlgorithmIdentifier::decode(&mut d).is_err());
    }
}
