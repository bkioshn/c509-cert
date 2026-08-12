//! Small shared building blocks used throughout the C509 grammar.

use minicbor::data::{Tag, Type};
use minicbor::Decoder;

use crate::error::{Error, Result};
use crate::oid::Oid;

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
pub(crate) fn read_biguint(d: &mut Decoder<'_>) -> Result<Vec<u8>> {
    Ok(d.bytes()?.to_vec())
}

/// Decode `~time`: an unwrapped CBOR epoch-based date/time whose content is
/// an unsigned integer (POSIX seconds).
pub(crate) fn read_time(d: &mut Decoder<'_>) -> Result<u64> {
    Ok(d.u64()?)
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
    Oid(Oid),
}

impl IntOrOid {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Bytes => Ok(IntOrOid::Oid(Oid::new(d.bytes()?.to_vec()))),
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
                e.bytes(oid.as_bytes())?;
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
    Mac(Vec<u8>),
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
                Ok(SpecialText::Mac(d.bytes()?.to_vec()))
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
            SpecialText::Mac(b) => {
                e.tag(Tag::new(MAC_ADDRESS_TAG))?.bytes(b)?;
            }
        }
        Ok(())
    }
}
