//! Small shared building blocks used throughout the C509 grammar.

use macaddr::MacAddr;
use minicbor::Decoder;
use minicbor::data::{Tag, Type};
use num_bigint::BigUint;
use oid::ObjectIdentifier;
use time::OffsetDateTime;

use crate::error::{Error, Result};

/// Decode a MAC address from its raw bytes: 6 bytes (48-bit) for EUI-48, 8 bytes (64-bit) for EUI-64.
pub(crate) fn decode_mac(bytes: &[u8]) -> Result<MacAddr> {
    match bytes.len() {
        6 => Ok(MacAddr::from(<[u8; 6]>::try_from(bytes).unwrap())),
        8 => Ok(MacAddr::from(<[u8; 8]>::try_from(bytes).unwrap())),
        _ => Err(Error::malformed("MAC address must be 6 or 8 bytes")),
    }
}

/// Decode an OID from a CBOR byte string holding its DER content octets.
pub(crate) fn decode_oid(d: &mut Decoder<'_>) -> Result<ObjectIdentifier> {
    ObjectIdentifier::try_from(d.bytes()?).map_err(|_| Error::malformed("invalid OID"))
}

/// The DER content octets of an [`ObjectIdentifier`], as written into a CBOR byte string.
pub(crate) fn oid_bytes(oid: &ObjectIdentifier) -> Vec<u8> {
    Vec::from(oid)
}

/// CBOR tag for a CBOR-tagged MAC address (EUI-48/EUI-64).
pub const MAC_ADDRESS_TAG: u64 = 48;

/// Read a CBOR array header and return its element count. Indefinite-length
/// arrays are rejected, since this crate always expects definite lengths.
pub(crate) fn definite_array_len(d: &mut Decoder<'_>) -> Result<u64> {
    d.array()?.ok_or(Error::malformed(
        "indefinite-length arrays are not supported",
    ))
}

/// Decode a big-endian unsigned integer from a CBOR byte string.
pub(crate) fn read_biguint(d: &mut Decoder<'_>) -> Result<BigUint> {
    Ok(BigUint::from_bytes_be(d.bytes()?))
}

/// The big-endian bytes of a [`BigUint`], as written into a CBOR byte string.
pub(crate) fn biguint_bytes(n: &BigUint) -> Vec<u8> {
    n.to_bytes_be()
}

/// Decode a timestamp from a CBOR unsigned integer of POSIX seconds.
pub(crate) fn read_time(d: &mut Decoder<'_>) -> Result<OffsetDateTime> {
    let secs =
        i64::try_from(d.u64()?).map_err(|_| Error::malformed("POSIX timestamp out of range"))?;
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|_| Error::malformed("POSIX timestamp out of range"))
}

/// Encode an [`OffsetDateTime`] as a CBOR unsigned integer of POSIX seconds.
pub(crate) fn encode_time<W: minicbor::encode::Write>(
    e: &mut minicbor::Encoder<W>,
    dt: OffsetDateTime,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    let secs = dt.unix_timestamp();
    let secs = u64::try_from(secs)
        .map_err(|_| minicbor::encode::Error::message("validity time predates the Unix epoch"))?;
    e.u64(secs)?;
    Ok(())
}

/// Capture one CBOR data item as raw bytes, for values this crate doesn't
/// decode into a typed form.
pub(crate) fn raw_item(d: &mut Decoder<'_>) -> Result<Vec<u8>> {
    let start = d.position();
    d.skip()?;
    Ok(d.input()[start..d.position()].to_vec())
}

/// Write back a previously-captured [`raw_item`].
pub(crate) fn write_raw<W: minicbor::encode::Write>(
    e: &mut minicbor::Encoder<W>,
    bytes: &[u8],
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.writer_mut()
        .write_all(bytes)
        .map_err(minicbor::encode::Error::write)
}

/// A C509 identifier that's either a registry-assigned int or, if unregistered, a raw OID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntOrOid {
    /// A registry-assigned integer value.
    Int(i32),
    /// An unregistered OID value.
    Oid(ObjectIdentifier),
}

impl IntOrOid {
    /// Decode an [`IntOrOid`] from a CBOR data item.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Bytes => Ok(IntOrOid::Oid(decode_oid(d)?)),
            _ => Ok(IntOrOid::Int(d.i32()?)),
        }
    }

    /// Encode an [`IntOrOid`] as a CBOR data item.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            IntOrOid::Int(n) => {
                e.i32(*n)?;
            }
            IntOrOid::Oid(oid) => {
                e.bytes(&oid_bytes(oid))?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for IntOrOid {
    /// Decode an [`IntOrOid`] from a CBOR data item.
    fn decode(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> core::result::Result<Self, minicbor::decode::Error> {
        match IntOrOid::decode(d) {
            Ok(v) => Ok(v),
            Err(Error::Cbor(e)) => Err(e),
            Err(Error::Malformed(m)) => Err(minicbor::decode::Error::message(m)),
        }
    }
}

impl<C> minicbor::Encode<C> for IntOrOid {
    /// Encode an [`IntOrOid`] as a CBOR data item.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        IntOrOid::encode(self, e)
    }
}

/// An RDN attribute value: plain text, raw bytes (used when the text looked
/// like hex), or a tagged MAC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialText {
    /// A plain text string.
    Text(String),
    /// Raw bytes (used when the text looked like hex).
    Bytes(Vec<u8>),
    /// A tagged MAC address.
    Mac(MacAddr),
}

impl SpecialText {
    /// Decode a [`SpecialText`] from a CBOR data item.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::String => Ok(SpecialText::Text(d.str()?.to_string())),
            Type::Bytes => Ok(SpecialText::Bytes(d.bytes()?.to_vec())),
            Type::Tag => {
                let tag = d.tag()?;
                if tag != Tag::new(MAC_ADDRESS_TAG) {
                    return Err(Error::malformed("unexpected tag in SpecialText"));
                }
                Ok(SpecialText::Mac(decode_mac(d.bytes()?)?))
            }
            _ => Err(Error::malformed(
                "expected text, bytes or tag for SpecialText",
            )),
        }
    }

    /// The text value, if this is the `Text` variant.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            SpecialText::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Encode a [`SpecialText`] as a CBOR data item.
    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            SpecialText::Text(s) => {
                e.str(s)?;
            }
            SpecialText::Bytes(b) => {
                e.bytes(b)?;
            }
            SpecialText::Mac(mac) => {
                e.tag(Tag::new(MAC_ADDRESS_TAG))?.bytes(mac.as_bytes())?;
            }
        }
        Ok(())
    }
}
