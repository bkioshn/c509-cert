//! RFC 3779 `IPAddrBlocks` / `ASIdentifiers` encoding used by the
//! `id-pe-ipAddrBlocks(-v2)` and `id-pe-autonomousSysIds(-v2)` extensions
//! (Section 3.3, extension registry values 32-35).
//!
//! Both the address and AS-number forms share the same "delta chain" idea:
//! the first value in a list is absolute, every later value is the CBOR int
//! *difference* from the value immediately before it (Section 3.3: "each
//! subsequent IPAddress SHALL be encoded as a CBOR integer representing the
//! difference from the previous IPAddress").
//!
//! For addresses, the ASN.1 BIT STRING value is additionally reduced to
//! `unusedBits || value` and, only when every entry in a family's address
//! list fits within 8 octets that way, further compacted into a delta-coded
//! CBOR int by prefixing `unusedBits + 1` (the `+1` guarantees the leading
//! byte is non-zero so the big-endian integer round-trips losslessly).
//! Larger addresses (e.g. most full IPv6 values) use the direct
//! `unusedBits || value` byte-string form instead, uniformly for the whole
//! family, per Section 3.3.

use minicbor::data::{Int, Type};
use minicbor::{Decoder, Encoder};

use crate::error::{Error, Result};

/// The CBOR int delta form is only used when the whole `(unusedBits + 1) ||
/// value` byte sequence fits in this many octets (i.e. fits a CBOR major
/// type 0/1 integer).
const MAX_INT_FORM_BYTES: usize = 8;

/// A normalized RFC 3779 address value: the `unusedBits || value` byte
/// sequence of the underlying ASN.1 BIT STRING, regardless of which CBOR
/// wire form (delta-coded int, or raw bytes) it was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressPrefix {
    pub unused_bits: u8,
    pub bytes: Vec<u8>,
}

impl AddressPrefix {
    /// Number of significant prefix bits (`8 * bytes.len() - unused_bits`).
    pub fn prefix_len(&self) -> usize {
        self.bytes.len() * 8 - self.unused_bits as usize
    }

    fn framed_len(&self) -> usize {
        self.bytes.len() + 1
    }

    fn from_absolute_int(abs: i128) -> Result<Self> {
        if abs < 0 {
            return Err(Error::malformed("resolved IP address delta is negative"));
        }
        let full = (abs as u128).to_be_bytes();
        let mut v: Vec<u8> = full.to_vec();
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        let framing = v[0];
        let unused_bits = framing
            .checked_sub(1)
            .ok_or_else(|| Error::malformed("invalid unusedBits+1 framing byte"))?;
        Ok(AddressPrefix {
            unused_bits,
            bytes: v[1..].to_vec(),
        })
    }

    fn to_absolute_int(&self) -> Result<i128> {
        if self.framed_len() > MAX_INT_FORM_BYTES {
            return Err(Error::malformed("address does not fit the CBOR int delta form"));
        }
        let mut v = Vec::with_capacity(self.framed_len());
        v.push(self.unused_bits.checked_add(1).ok_or_else(|| {
            Error::malformed("unusedBits too large to use the CBOR int delta form")
        })?);
        v.extend_from_slice(&self.bytes);
        let mut buf = [0u8; 16];
        buf[16 - v.len()..].copy_from_slice(&v);
        Ok(u128::from_be_bytes(buf) as i128)
    }

    fn from_raw_bytes(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() {
            return Err(Error::malformed("empty RFC 3779 address byte string"));
        }
        Ok(AddressPrefix {
            unused_bits: raw[0],
            bytes: raw[1..].to_vec(),
        })
    }

    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.framed_len());
        v.push(self.unused_bits);
        v.extend_from_slice(&self.bytes);
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddressOrRange {
    Prefix(AddressPrefix),
    Range { min: AddressPrefix, max: AddressPrefix },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddressChoice {
    /// `inherit` — this address family is inherited from the issuer.
    Inherit,
    Prefixes(Vec<IpAddressOrRange>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressFamily {
    pub afi: u16,
    pub safi: Option<u16>,
    pub choice: IpAddressChoice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsIdOrRange {
    Id(u64),
    Range { min: u64, max: u64 },
}

fn is_numeric_type(ty: Type) -> bool {
    matches!(
        ty,
        Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::Int
    )
}

fn encode_delta<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    delta: i128,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    let int_val =
        Int::try_from(delta).map_err(|_| minicbor::encode::Error::message("delta out of CBOR int range"))?;
    e.int(int_val)?;
    Ok(())
}

// ---- IPAddrBlocks -----------------------------------------------------

pub(crate) fn decode_ip_address_families(d: &mut Decoder<'_>) -> Result<Vec<IpAddressFamily>> {
    let len = crate::common::definite_array_len(d)?;
    if len % 3 != 0 {
        return Err(Error::malformed("IPAddrBlocks array length must be a multiple of 3"));
    }
    let mut out = Vec::with_capacity((len / 3) as usize);
    for _ in 0..(len / 3) {
        let afi = d.u16()?;
        let safi = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(d.u16()?)
        };
        let choice = decode_ip_address_choice(d)?;
        out.push(IpAddressFamily { afi, safi, choice });
    }
    Ok(out)
}

fn decode_ip_address_choice(d: &mut Decoder<'_>) -> Result<IpAddressChoice> {
    if d.datatype()? == Type::Null {
        d.null()?;
        return Ok(IpAddressChoice::Inherit);
    }
    let len = crate::common::definite_array_len(d)?;
    if len == 0 {
        return Ok(IpAddressChoice::Prefixes(Vec::new()));
    }
    let is_int_form = {
        let mut p = d.probe();
        match p.datatype()? {
            Type::Array | Type::ArrayIndef => {
                crate::common::definite_array_len(&mut p)?;
                is_numeric_type(p.datatype()?)
            }
            ty => is_numeric_type(ty),
        }
    };

    let mut entries = Vec::with_capacity(len as usize);
    let mut previous: i128 = 0;
    let mut first = true;
    for _ in 0..len {
        if is_int_form {
            match d.datatype()? {
                Type::Array | Type::ArrayIndef => {
                    let n = crate::common::definite_array_len(d)?;
                    if n != 2 {
                        return Err(Error::malformed("IntAddressRange must have 2 elements"));
                    }
                    let min_raw = i128::from(d.int()?);
                    let min_abs = if first { min_raw } else { previous + min_raw };
                    previous = min_abs;
                    first = false;
                    let max_raw = i128::from(d.int()?);
                    let max_abs = previous + max_raw;
                    previous = max_abs;
                    entries.push(IpAddressOrRange::Range {
                        min: AddressPrefix::from_absolute_int(min_abs)?,
                        max: AddressPrefix::from_absolute_int(max_abs)?,
                    });
                }
                _ => {
                    let raw = i128::from(d.int()?);
                    let abs = if first { raw } else { previous + raw };
                    previous = abs;
                    first = false;
                    entries.push(IpAddressOrRange::Prefix(AddressPrefix::from_absolute_int(abs)?));
                }
            }
        } else {
            match d.datatype()? {
                Type::Array | Type::ArrayIndef => {
                    let n = crate::common::definite_array_len(d)?;
                    if n != 2 {
                        return Err(Error::malformed("AddressRange must have 2 elements"));
                    }
                    let min = AddressPrefix::from_raw_bytes(d.bytes()?)?;
                    let max = AddressPrefix::from_raw_bytes(d.bytes()?)?;
                    entries.push(IpAddressOrRange::Range { min, max });
                }
                _ => {
                    let p = AddressPrefix::from_raw_bytes(d.bytes()?)?;
                    entries.push(IpAddressOrRange::Prefix(p));
                }
            }
        }
    }
    Ok(IpAddressChoice::Prefixes(entries))
}

pub(crate) fn encode_ip_address_families<W: minicbor::encode::Write>(
    families: &[IpAddressFamily],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(families.len() as u64 * 3)?;
    for fam in families {
        e.u16(fam.afi)?;
        match fam.safi {
            Some(s) => {
                e.u16(s)?;
            }
            None => {
                e.null()?;
            }
        }
        encode_ip_address_choice(&fam.choice, e)?;
    }
    Ok(())
}

fn encode_ip_address_choice<W: minicbor::encode::Write>(
    choice: &IpAddressChoice,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match choice {
        IpAddressChoice::Inherit => {
            e.null()?;
        }
        IpAddressChoice::Prefixes(entries) => {
            let use_int_form = entries.iter().all(|entry| match entry {
                IpAddressOrRange::Prefix(p) => p.framed_len() <= MAX_INT_FORM_BYTES,
                IpAddressOrRange::Range { min, max } => {
                    min.framed_len() <= MAX_INT_FORM_BYTES && max.framed_len() <= MAX_INT_FORM_BYTES
                }
            });
            e.array(entries.len() as u64)?;
            if use_int_form {
                let mut previous: i128 = 0;
                let mut first = true;
                for entry in entries {
                    match entry {
                        IpAddressOrRange::Prefix(p) => {
                            let abs = p
                                .to_absolute_int()
                                .map_err(|_| minicbor::encode::Error::message("bad address prefix"))?;
                            let delta = if first { abs } else { abs - previous };
                            previous = abs;
                            first = false;
                            encode_delta(e, delta)?;
                        }
                        IpAddressOrRange::Range { min, max } => {
                            let min_abs = min
                                .to_absolute_int()
                                .map_err(|_| minicbor::encode::Error::message("bad address prefix"))?;
                            let min_delta = if first { min_abs } else { min_abs - previous };
                            previous = min_abs;
                            first = false;
                            let max_abs = max
                                .to_absolute_int()
                                .map_err(|_| minicbor::encode::Error::message("bad address prefix"))?;
                            let max_delta = max_abs - previous;
                            previous = max_abs;
                            e.array(2)?;
                            encode_delta(e, min_delta)?;
                            encode_delta(e, max_delta)?;
                        }
                    }
                }
            } else {
                for entry in entries {
                    match entry {
                        IpAddressOrRange::Prefix(p) => {
                            e.bytes(&p.to_raw_bytes())?;
                        }
                        IpAddressOrRange::Range { min, max } => {
                            e.array(2)?;
                            e.bytes(&min.to_raw_bytes())?;
                            e.bytes(&max.to_raw_bytes())?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ---- ASIdentifiers ------------------------------------------------------

pub(crate) fn decode_as_identifiers(d: &mut Decoder<'_>) -> Result<Option<Vec<AsIdOrRange>>> {
    if d.datatype()? == Type::Null {
        d.null()?;
        return Ok(None);
    }
    let len = crate::common::definite_array_len(d)?;
    let mut out = Vec::with_capacity(len as usize);
    let mut previous: i128 = 0;
    let mut first = true;
    for _ in 0..len {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => {
                let n = crate::common::definite_array_len(d)?;
                if n != 2 {
                    return Err(Error::malformed("AS id range must have 2 elements"));
                }
                let min_raw = i128::from(d.int()?);
                let min_abs = if first { min_raw } else { previous + min_raw };
                previous = min_abs;
                first = false;
                let max_raw = i128::from(d.int()?);
                let max_abs = previous + max_raw;
                previous = max_abs;
                out.push(AsIdOrRange::Range {
                    min: u64::try_from(min_abs).map_err(|_| Error::malformed("AS id out of range"))?,
                    max: u64::try_from(max_abs).map_err(|_| Error::malformed("AS id out of range"))?,
                });
            }
            _ => {
                let raw = i128::from(d.int()?);
                let abs = if first { raw } else { previous + raw };
                previous = abs;
                first = false;
                out.push(AsIdOrRange::Id(
                    u64::try_from(abs).map_err(|_| Error::malformed("AS id out of range"))?,
                ));
            }
        }
    }
    Ok(Some(out))
}

pub(crate) fn encode_as_identifiers<W: minicbor::encode::Write>(
    value: &Option<Vec<AsIdOrRange>>,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match value {
        None => {
            e.null()?;
        }
        Some(ids) => {
            e.array(ids.len() as u64)?;
            let mut previous: i128 = 0;
            let mut first = true;
            for id in ids {
                match id {
                    AsIdOrRange::Id(v) => {
                        let abs = *v as i128;
                        let delta = if first { abs } else { abs - previous };
                        previous = abs;
                        first = false;
                        encode_delta(e, delta)?;
                    }
                    AsIdOrRange::Range { min, max } => {
                        let min_abs = *min as i128;
                        let min_delta = if first { min_abs } else { min_abs - previous };
                        previous = min_abs;
                        first = false;
                        let max_abs = *max as i128;
                        let max_delta = max_abs - previous;
                        previous = max_abs;
                        e.array(2)?;
                        encode_delta(e, min_delta)?;
                        encode_delta(e, max_delta)?;
                    }
                }
            }
        }
    }
    Ok(())
}
