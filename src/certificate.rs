//! `C509Certificate` / `TBSCertificate` (Section 3.1, Figure 1).
//!
//! ```text
//! C509Certificate = [
//!    TBSCertificate,
//!    issuerSignatureValue : any,
//! ]
//!
//! ; The elements of the following group are used in a CBOR Sequence:
//! TBSCertificate = (
//!    c509CertificateType: int,
//!    certificateSerialNumber: CertificateSerialNumber,
//!    issuerSignatureAlgorithm: AlgorithmIdentifier,
//!    issuer: Name / null,
//!    validityNotBefore: ~time,
//!    validityNotAfter: ~time / null,
//!    subject: Name,
//!    subjectPublicKeyAlgorithm: AlgorithmIdentifier,
//!    subjectPublicKey: Defined,
//!    extensions: Extensions,
//! )
//! ```

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use num_bigint::BigUint;
use time::OffsetDateTime;

use crate::algorithm::AlgorithmIdentifier;
use crate::common;
use crate::error::{Error, Result};
use crate::extensions::Extensions;
use crate::name::Name;

/// The number of fields represent in array form.
const FIELD_COUNT: u64 = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbsCertificate {
    /// The X.509 certificate type `2` for natively signed certificate
    /// `3` for a CBOR re-encoding of a DER-encoded certificate.
    pub c509_certificate_type: i32,
    /// `biguint`: Certificate serial number unwrapped CBOR unsigned bignum.
    ///  Big-endian magnitude, no leading `0x00` byte.
    pub certificate_serial_number: BigUint,
    /// `AlgorithmIdentifier`: the signature algorithm used to sign the
    /// certificate.
    pub issuer_signature_algorithm: AlgorithmIdentifier,
    /// `None` means "identical to `subject`" (self-signed).
    pub issuer: Option<Name>,
    /// Certificate valid from this date and time.
    pub validity_not_before: OffsetDateTime,
    /// Certificate expiration this date and time.
    /// `None` means "no expiration" (X.509 `99991231235959Z`).
    pub validity_not_after: Option<OffsetDateTime>,
    /// The certificate subject.
    pub subject: Name,
    /// The algorithm used to encode the subject public key.
    pub subject_public_key_algorithm: AlgorithmIdentifier,
    /// The certificate subject public key.
    pub subject_public_key: Vec<u8>,
    /// The certificate extensions.
    pub extensions: Extensions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C509Certificate {
    /// The TBS (To Be Signed) certificate.
    pub tbs: TbsCertificate,
    /// The certificate issuer signature value.
    pub issuer_signature_value: Vec<u8>,
}

impl C509Certificate {
    /// Decode a `C509Certificate` CBOR item (the wrapped array form:
    /// `[ TBSCertificate, issuerSignatureValue ]`, i.e. one 11-element
    /// array on the wire).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        minicbor::decode(bytes).map_err(Error::from)
    }

    /// Decode the "unwrapped `C509Certificate`" form used throughout the
    /// draft's own examples: an RFC 8742 CBOR Sequence of the same 11 items,
    /// with **no** outer array header.
    pub fn decode_sequence(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        Self::decode_fields(&mut d)
    }

    /// Encode as the wrapped `C509Certificate` CBOR array item.
    pub fn encode(&self) -> Vec<u8> {
        minicbor::to_vec(self).expect("Vec<u8> writer is infallible")
    }

    /// Encode as the bare 11-item CBOR Sequence (no outer array header).
    /// This is the byte string that natively signed certificates are
    /// signed over (Section 3.1.12).
    pub fn encode_sequence(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        self.encode_fields(&mut e)
            .expect("Vec<u8> writer is infallible");
        buf
    }

    /// Decode the fields of a `C509Certificate` CBOR item.
    fn decode_fields(d: &mut Decoder<'_>) -> Result<Self> {
        let c509_certificate_type = d.i32()?;
        let certificate_serial_number = common::read_biguint(d)?;
        let issuer_signature_algorithm = AlgorithmIdentifier::decode(d)?;
        let issuer = Name::decode_optional(d)?;
        let validity_not_before = common::read_time(d)?;
        let validity_not_after = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(common::read_time(d)?)
        };
        let subject = Name::decode(d)?;
        let subject_public_key_algorithm = AlgorithmIdentifier::decode(d)?;
        let subject_public_key = d.bytes()?.to_vec();
        let extensions = Extensions::decode(d)?;
        let issuer_signature_value = d.bytes()?.to_vec();
        Ok(C509Certificate {
            tbs: TbsCertificate {
                c509_certificate_type,
                certificate_serial_number,
                issuer_signature_algorithm,
                issuer,
                validity_not_before,
                validity_not_after,
                subject,
                subject_public_key_algorithm,
                subject_public_key,
                extensions,
            },
            issuer_signature_value,
        })
    }

    /// Encode the fields of a `C509Certificate` CBOR item.
    fn encode_fields<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.i32(self.tbs.c509_certificate_type)?;
        e.bytes(&common::biguint_bytes(&self.tbs.certificate_serial_number))?;
        self.tbs.issuer_signature_algorithm.encode(e)?;
        Name::encode_optional(&self.tbs.issuer, e)?;
        common::encode_time(e, self.tbs.validity_not_before)?;
        match self.tbs.validity_not_after {
            Some(t) => {
                common::encode_time(e, t)?;
            }
            None => {
                e.null()?;
            }
        }
        self.tbs.subject.encode(e)?;
        self.tbs.subject_public_key_algorithm.encode(e)?;
        e.bytes(&self.tbs.subject_public_key)?;
        self.tbs.extensions.encode(e)?;
        e.bytes(&self.issuer_signature_value)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for C509Certificate {
    /// Decode a `C509Certificate` CBOR item.
    fn decode(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
        let n = d.array()?.ok_or_else(|| {
            minicbor::decode::Error::message("C509Certificate must be a definite-length array")
        })?;
        if n != FIELD_COUNT {
            return Err(minicbor::decode::Error::message(format!(
                "C509Certificate array must have exactly {FIELD_COUNT} elements, got {n}"
            )));
        }
        Self::decode_fields(d).map_err(Error::into_minicbor)
    }
}

impl<C> minicbor::Encode<C> for C509Certificate {
    /// Encode a `C509Certificate` CBOR item.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(FIELD_COUNT)?;
        self.encode_fields(e)
    }
}
