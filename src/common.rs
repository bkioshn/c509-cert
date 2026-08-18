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

/// An `attributeValue`: [`SpecialText`] and `Vec<u8>` decode/encode a single
/// value; `Vec<T>` for any `T: RdnValue` wraps it in the `[ + T ]` array form
/// used by the multi-valued `RDNAttributes`.
pub trait RdnValue: Sized {
    fn decode(d: &mut Decoder<'_>) -> Result<Self>;
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>>;
}

impl RdnValue for SpecialText {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        SpecialText::decode(d)
    }

    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        SpecialText::encode(self, e)
    }
}

impl RdnValue for Vec<u8> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(d.bytes()?.to_vec())
    }

    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(self)?;
        Ok(())
    }
}

impl<T: RdnValue> RdnValue for Vec<T> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let n = definite_array_len(d)?;
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(T::decode(d)?);
        }
        Ok(out)
    }

    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len() as u64)?;
        for v in self {
            v.encode(e)?;
        }
        Ok(())
    }
}

/// `RDNAttribute` ([`crate::name::RdnAttribute`], single-valued: `S`/`B` are
/// bare values) and `RDNAttributes` ([`crate::extensions::RdnAttributes`],
/// multi-valued: `S`/`B` are `Vec`s) share this shape:
/// `( attributeType: int, attributeValue: S ) // ( attributeType: ~oid, attributeValue: B )`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdnAttr<S, B> {
    Registered {
        id: u16,
        printable_string: bool,
        value: S,
    },
    Oid {
        oid: ObjectIdentifier,
        value: B,
    },
}

impl<S: RdnValue, B: RdnValue> RdnAttr<S, B> {
    /// Decode a `RdnAttr`. The `attributeType`'s sign selects `printableString`
    /// (negative) vs `utf8String` (positive) for the registered-id form.
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Bytes => {
                let oid = decode_oid(d)?;
                Ok(RdnAttr::Oid {
                    oid,
                    value: B::decode(d)?,
                })
            }
            _ => {
                let raw = d.i32()?;
                Ok(RdnAttr::Registered {
                    id: raw.unsigned_abs() as u16,
                    printable_string: raw < 0,
                    value: S::decode(d)?,
                })
            }
        }
    }

    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            RdnAttr::Registered {
                id,
                printable_string,
                value,
            } => {
                let raw = if *printable_string {
                    -(*id as i32)
                } else {
                    *id as i32
                };
                e.i32(raw)?;
                value.encode(e)?;
            }
            RdnAttr::Oid { oid, value } => {
                e.bytes(&oid_bytes(oid))?;
                value.encode(e)?;
            }
        }
        Ok(())
    }
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

/// Read a CBOR array header and error if its element count isn't `want`.
pub(crate) fn expect_array_len(d: &mut Decoder<'_>, want: u64) -> Result<()> {
    let len = definite_array_len(d)?;
    if len != want {
        return Err(Error::malformed("unexpected array length"));
    }
    Ok(())
}

/// Decode a `uint / null` field into an `Option<u32>`.
pub(crate) fn decode_opt_uint(d: &mut Decoder<'_>) -> Result<Option<u32>> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        Ok(Some(d.u32()?))
    }
}

/// Encode an `Option<u32>` as the `uint / null` field read by [`decode_opt_uint`].
pub(crate) fn encode_opt_uint<W: minicbor::encode::Write>(
    e: &mut minicbor::Encoder<W>,
    v: Option<u32>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match v {
        Some(n) => {
            e.u32(n)?;
        }
        None => {
            e.null()?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use minicbor::Encoder;

    use super::*;

    #[test]
    fn decode_mac_eui48() {
        // Arbitrary EUI-48 address.
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(decode_mac(&bytes).unwrap(), MacAddr::from(bytes));
    }

    #[test]
    fn decode_mac_eui64() {
        // Arbitrary EUI-64 address.
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(decode_mac(&bytes).unwrap(), MacAddr::from(bytes));
    }

    #[test]
    fn decode_mac_wrong_length_is_malformed() {
        // Arbitrary 3 bytes, is too short for an EUI-48 or EUI-64 address.
        assert!(decode_mac(&[0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn oid_roundtrip() {
        let oid = ObjectIdentifier::try_from("1.2.840.113549.1.1.1").unwrap();

        let mut buf = Vec::new();
        Encoder::new(&mut buf).bytes(&oid_bytes(&oid)).unwrap();
        let mut d = Decoder::new(&buf);
        assert_eq!(decode_oid(&mut d).unwrap(), oid);
    }

    #[test]
    fn definite_array_len_reads_count() {
        let mut buf = Vec::new();
        Encoder::new(&mut buf).array(3).unwrap();
        let mut d = Decoder::new(&buf);
        assert_eq!(definite_array_len(&mut d).unwrap(), 3);
    }

    #[test]
    fn definite_array_len_rejects_indefinite() {
        let mut buf = Vec::new();
        Encoder::new(&mut buf).begin_array().unwrap();
        let mut d = Decoder::new(&buf);
        assert!(definite_array_len(&mut d).is_err());
    }

    #[test]
    fn biguint_roundtrip() {
        let n = BigUint::from(0x0102_0304_0506_u64);

        let mut buf = Vec::new();
        Encoder::new(&mut buf).bytes(&biguint_bytes(&n)).unwrap();
        let mut d = Decoder::new(&buf);
        assert_eq!(read_biguint(&mut d).unwrap(), n);
    }

    #[test]
    fn time_roundtrip() {
        let dt = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        encode_time(&mut e, dt).unwrap();
        let mut d = Decoder::new(&buf);
        assert_eq!(read_time(&mut d).unwrap(), dt);
    }

    #[test]
    fn encode_time_rejects_pre_epoch() {
        let dt = OffsetDateTime::from_unix_timestamp(-1).unwrap();

        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        assert!(encode_time(&mut e, dt).is_err());
    }

    #[test]
    fn raw_item_roundtrip() {
        let mut buf = Vec::new();
        Encoder::new(&mut buf).u32(42).unwrap();
        let mut d = Decoder::new(&buf);
        let captured = raw_item(&mut d).unwrap();
        assert_eq!(captured, buf);

        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        write_raw(&mut e, &captured).unwrap();
        assert_eq!(out, buf);
    }

    fn roundtrip_int_or_oid(value: IntOrOid) -> IntOrOid {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        value.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        IntOrOid::decode(&mut d).unwrap()
    }

    #[test]
    fn int_or_oid_int_form() {
        let value = IntOrOid::Int(-7);
        assert_eq!(roundtrip_int_or_oid(value.clone()), value);
    }

    #[test]
    fn int_or_oid_oid_form() {
        let oid = ObjectIdentifier::try_from("1.2.840.113549.1.1.1").unwrap();
        let value = IntOrOid::Oid(oid);
        assert_eq!(roundtrip_int_or_oid(value.clone()), value);
    }

    fn roundtrip_special_text(value: SpecialText) -> SpecialText {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        value.encode(&mut e).unwrap();
        let mut d = Decoder::new(&buf);
        SpecialText::decode(&mut d).unwrap()
    }

    #[test]
    fn special_text_text_form() {
        let value = SpecialText::Text("hello".to_string());
        assert_eq!(roundtrip_special_text(value.clone()), value);
        assert_eq!(value.as_text(), Some("hello"));
    }

    #[test]
    fn special_text_bytes_form() {
        let value = SpecialText::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(roundtrip_special_text(value.clone()), value);
        assert_eq!(value.as_text(), None);
    }

    #[test]
    fn special_text_mac_form() {
        let value = SpecialText::Mac(MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        assert_eq!(roundtrip_special_text(value.clone()), value);
    }

    #[test]
    fn special_text_rejects_unexpected_tag() {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        e.tag(Tag::new(1)).unwrap().bytes(&[0x01]).unwrap();
        let mut d = Decoder::new(&buf);
        assert!(SpecialText::decode(&mut d).is_err());
    }
}
