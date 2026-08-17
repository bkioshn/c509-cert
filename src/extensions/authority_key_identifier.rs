//! `AuthorityKeyIdentifier` (id 7).
//! `AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier`

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use num_bigint::BigUint;

use super::general_name::{GeneralName, decode_general_names, encode_general_names};
use crate::common;
use crate::error::Result;

/// An `AuthorityKeyIdentifier`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKeyIdentifier {
    /// The key identifier.
    pub key_identifier: Vec<u8>,
    /// The certificate issuer.
    pub cert_issuer: Option<Vec<GeneralName>>,
    /// The certificate serial number.
    pub cert_serial: Option<BigUint>,
}

impl AuthorityKeyIdentifier {
    /// Decode an `AuthorityKeyIdentifier`.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Bytes => Ok(AuthorityKeyIdentifier {
                key_identifier: d.bytes()?.to_vec(),
                cert_issuer: None,
                cert_serial: None,
            }),
            _ => {
                super::expect_array_len(d, 3)?;
                let key_identifier = d.bytes()?.to_vec();
                let cert_issuer = Some(decode_general_names(d)?);
                let cert_serial = Some(common::read_biguint(d)?);
                Ok(AuthorityKeyIdentifier {
                    key_identifier,
                    cert_issuer,
                    cert_serial,
                })
            }
        }
    }

    /// Encode an `AuthorityKeyIdentifier`.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match (&self.cert_issuer, &self.cert_serial) {
            (None, None) => {
                e.bytes(&self.key_identifier)?;
            }
            (Some(issuer), Some(serial)) => {
                e.array(3)?;
                e.bytes(&self.key_identifier)?;
                encode_general_names(issuer, e)?;
                e.bytes(&common::biguint_bytes(serial))?;
            }
            _ => {
                return Err(minicbor::encode::Error::message(
                    "AuthorityKeyIdentifier requires both cert_issuer and cert_serial, or neither",
                ));
            }
        }
        Ok(())
    }
}
