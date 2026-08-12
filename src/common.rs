//! Small shared building blocks used throughout the C509 grammar.

use macaddr::MacAddr;
use minicbor::data::{Tag, Type};
use minicbor::Decoder;
use num_bigint::BigUint;
use oid::ObjectIdentifier;
use time::OffsetDateTime;

use crate::error::{Error, Result};

/// Decode a tag-48 wrapped EUI-48 (6-byte) or EUI-64 (8-byte) MAC address
/// (RFC 9542 Section 2.4).
pub(crate) fn decode_mac(bytes: &[u8]) -> Result<MacAddr> {
    match bytes.len() {
        6 => Ok(MacAddr::from(<[u8; 6]>::try_from(bytes).unwrap())),
        8 => Ok(MacAddr::from(<[u8; 8]>::try_from(bytes).unwrap())),
        _ => Err(Error::malformed("MAC address must be 6 or 8 bytes")),
    }
}

/// Decode `~oid`: an unwrapped CBOR OID, i.e. a plain byte string holding
/// the DER content octets (base-128 arc encoding) of an OBJECT IDENTIFIER,
/// with no CBOR tag and no DER tag/length header.
pub(crate) fn decode_oid(d: &mut Decoder<'_>) -> Result<ObjectIdentifier> {
    ObjectIdentifier::try_from(d.bytes()?).map_err(|_| Error::malformed("invalid OID encoding"))
}

/// The `~oid` wire encoding of an [`ObjectIdentifier`]: its DER content
/// octets, with no CBOR tag and no DER tag/length header.
pub(crate) fn oid_bytes(oid: &ObjectIdentifier) -> Vec<u8> {
    Vec::from(oid)
}

/// The CBOR tag used for CBOR-tagged MAC addresses (EUI-48/EUI-64), as
/// referenced by `SpecialText` in Section 3.1.4 of the C509 draft; see
/// RFC 9542 Section 2.4.
pub const MAC_ADDRESS_TAG: u64 = 48;

/// Read a definite-length CBOR array header, returning the element count.
///
/// C509's recommended "deterministic encoding" (Section 3.7) always uses
/// definite-length arrays; this parser requires definite lengths for the
/// hand-rolled "flattened pair list" grammars (RDN attributes, extensions,
/// general names, ...) where heterogeneous element types make indefinite
/// iteration impractical to support safely.
pub(crate) fn definite_array_len(d: &mut Decoder<'_>) -> Result<u64> {
    d.array()?
        .ok_or(Error::malformed("indefinite-length arrays are not supported"))
}

/// Decode `~biguint`: an unwrapped CBOR unsigned bignum, i.e. a plain byte
/// string holding the big-endian magnitude with no leading zero byte.
pub(crate) fn read_biguint(d: &mut Decoder<'_>) -> Result<BigUint> {
    Ok(BigUint::from_bytes_be(d.bytes()?))
}

/// The `~biguint` wire encoding of a [`BigUint`]: its big-endian magnitude,
/// with no leading zero byte (`BigUint::to_bytes_be` is already minimal).
pub(crate) fn biguint_bytes(n: &BigUint) -> Vec<u8> {
    n.to_bytes_be()
}

/// Decode `~time`: an unwrapped CBOR epoch-based date/time whose content is
/// an unsigned integer (POSIX seconds).
pub(crate) fn read_time(d: &mut Decoder<'_>) -> Result<OffsetDateTime> {
    let secs = i64::try_from(d.u64()?).map_err(|_| Error::malformed("POSIX timestamp out of range"))?;
    OffsetDateTime::from_unix_timestamp(secs).map_err(|_| Error::malformed("POSIX timestamp out of range"))
}

/// The `~time` wire encoding of an [`OffsetDateTime`]: POSIX seconds as an
/// unsigned CBOR int.
pub(crate) fn encode_time<W: minicbor::encode::Write>(
    e: &mut minicbor::Encoder<W>,
    dt: OffsetDateTime,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    let secs = dt.unix_timestamp();
    let secs = u64::try_from(secs).map_err(|_| minicbor::encode::Error::message("validity time predates the Unix epoch"))?;
    e.u64(secs)?;
    Ok(())
}

/// Capture one full CBOR data item verbatim (used as the fallback
/// representation for extension values / general names this crate does not
/// give a typed decoding to).
pub(crate) fn raw_item(d: &mut Decoder<'_>) -> Result<Vec<u8>> {
    let start = d.position();
    d.skip()?;
    Ok(d.input()[start..d.position()].to_vec())
}

/// Write back a previously-captured [`raw_item`] verbatim.
pub(crate) fn write_raw<W: minicbor::encode::Write>(
    e: &mut minicbor::Encoder<W>,
    bytes: &[u8],
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.writer_mut()
        .write_all(bytes)
        .map_err(minicbor::encode::Error::write)
}

/// `int / ~oid`: many C509 identifiers (attribute types, extension IDs, key
/// purposes, policy identifiers, access methods, ...) are encoded either as
/// a small CBOR int (looked up in the relevant IANA registry) or, when no
/// registry value exists, as the raw OID content octets (`~oid`).
///
/// The two alternatives are distinguished purely by CBOR major type: an
/// integer major type selects `Int`, a byte string major type selects
/// `Oid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntOrOid {
    Int(i32),
    Oid(ObjectIdentifier),
}

impl IntOrOid {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Bytes => Ok(IntOrOid::Oid(decode_oid(d)?)),
            _ => Ok(IntOrOid::Int(d.i32()?)),
        }
    }

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
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> core::result::Result<Self, minicbor::decode::Error> {
        match IntOrOid::decode(d) {
            Ok(v) => Ok(v),
            Err(Error::Cbor(e)) => Err(e),
            Err(Error::Malformed(m)) => Err(minicbor::decode::Error::message(m)),
        }
    }
}

impl<C> minicbor::Encode<C> for IntOrOid {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        IntOrOid::encode(self, e)
    }
}

/// `SpecialText = text / bytes / tag`
///
/// The final encoding of an RDN attribute value (Section 3.1.4): a UTF-8
/// text string, a byte string (used when the text looked like hex), or a
/// CBOR-tagged MAC address (tag 48, RFC 9542 Section 2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialText {
    Text(String),
    Bytes(Vec<u8>),
    /// Tag 48 wrapped EUI-48 (6 bytes) or EUI-64 (8 bytes) MAC address.
    Mac(MacAddr),
}

impl SpecialText {
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
            _ => Err(Error::malformed("expected text, bytes or tag for SpecialText")),
        }
    }

    /// The text value, if this is the `Text` variant.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            SpecialText::Text(s) => Some(s),
            _ => None,
        }
    }

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
