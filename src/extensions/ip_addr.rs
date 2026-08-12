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
//!
//! Addresses are exposed through [`ipnet::IpNet`] (for prefixes, which carry
//! a prefix length) and [`std::net::IpAddr`] (for arbitrary, not
//! necessarily prefix-aligned, ranges). Both require the family's AFI
//! (Section 3.3, IANA Address Family Identifiers) to be 1 (IPv4) or 2
//! (IPv6); other address families cannot be represented by these types and
//! are rejected with [`Error::Malformed`](crate::Error).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use minicbor::data::{Int, Type};
use minicbor::{Decoder, Encoder};

use crate::error::{Error, Result};

/// The CBOR int delta form is only used when the whole `(unusedBits + 1) ||
/// value` byte sequence fits in this many octets (i.e. fits a CBOR major
/// type 0/1 integer).
const MAX_INT_FORM_BYTES: usize = 8;

fn address_width(afi: u16) -> Result<usize> {
    match afi {
        1 => Ok(4),
        2 => Ok(16),
        _ => Err(Error::malformed(
            "unsupported address family for typed decoding (expected AFI 1 = IPv4 or 2 = IPv6)",
        )),
    }
}

/// Build a full-width address from the significant leading bytes of an RFC
/// 3779 address value, filling the remaining (unspecified) trailing bytes
/// with `fill` (`0x00` for a prefix or a range minimum, `0xFF` for a range
/// maximum).
fn build_addr(afi: u16, significant: &[u8], fill: u8) -> Result<IpAddr> {
    let width = address_width(afi)?;
    if significant.len() > width {
        return Err(Error::malformed("address value longer than its family's width"));
    }
    let mut buf = vec![fill; width];
    buf[..significant.len()].copy_from_slice(significant);
    Ok(match width {
        4 => IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])),
        _ => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&buf);
            IpAddr::V6(Ipv6Addr::from(arr))
        }
    })
}

fn build_prefix(afi: u16, significant: &[u8], unused_bits: u8) -> Result<IpNet> {
    let addr = build_addr(afi, significant, 0x00)?;
    let prefix_len = (significant.len() as u8)
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(unused_bits))
        .ok_or_else(|| Error::malformed("invalid RFC 3779 prefix length"))?;
    IpNet::new(addr, prefix_len).map_err(|_| Error::malformed("invalid RFC 3779 prefix length"))
}

/// Inverse of [`build_prefix`]: the significant leading bytes of the network
/// address (trimmed to `prefix_len`) plus the resulting `unusedBits`.
fn prefix_to_framed(net: &IpNet) -> (Vec<u8>, u8) {
    let full: Vec<u8> = match net.network() {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let prefix_len = net.prefix_len();
    let sig_len = prefix_len.div_ceil(8) as usize;
    let unused_bits = sig_len as u8 * 8 - prefix_len;
    (full[..sig_len].to_vec(), unused_bits)
}

/// Inverse of `build_addr`: strips whole trailing bytes equal to `fill`,
/// leaving the significant leading bytes.
fn addr_to_framed_trimmed(addr: &IpAddr, fill: u8) -> Vec<u8> {
    let full: Vec<u8> = match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let mut end = full.len();
    while end > 0 && full[end - 1] == fill {
        end -= 1;
    }
    full[..end].to_vec()
}

fn absolute_int_from_framed(significant: &[u8], unused_bits: u8) -> Result<i128> {
    let framed_len = significant.len() + 1;
    if framed_len > MAX_INT_FORM_BYTES {
        return Err(Error::malformed("address does not fit the CBOR int delta form"));
    }
    let mut v = Vec::with_capacity(framed_len);
    v.push(
        unused_bits
            .checked_add(1)
            .ok_or_else(|| Error::malformed("unusedBits too large to use the CBOR int delta form"))?,
    );
    v.extend_from_slice(significant);
    let mut buf = [0u8; 16];
    buf[16 - v.len()..].copy_from_slice(&v);
    Ok(u128::from_be_bytes(buf) as i128)
}

/// Inverse of [`absolute_int_from_framed`]: the significant leading bytes
/// and `unusedBits` encoded by a resolved delta-chain integer.
fn framed_from_absolute_int(abs: i128) -> Result<(Vec<u8>, u8)> {
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
    Ok((v[1..].to_vec(), unused_bits))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddressOrRange {
    /// A CIDR-style address prefix.
    Prefix(IpNet),
    /// An arbitrary (not necessarily prefix-aligned) address range.
    Range { min: IpAddr, max: IpAddr },
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

fn to_encode_err<W: minicbor::encode::Write>(_: Error) -> minicbor::encode::Error<W::Error> {
    minicbor::encode::Error::message("address value too large for the CBOR int delta form")
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
        let choice = decode_ip_address_choice(afi, d)?;
        out.push(IpAddressFamily { afi, safi, choice });
    }
    Ok(out)
}

fn decode_ip_address_choice(afi: u16, d: &mut Decoder<'_>) -> Result<IpAddressChoice> {
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
                    let (min_bytes, _) = framed_from_absolute_int(min_abs)?;
                    let (max_bytes, _) = framed_from_absolute_int(max_abs)?;
                    entries.push(IpAddressOrRange::Range {
                        min: build_addr(afi, &min_bytes, 0x00)?,
                        max: build_addr(afi, &max_bytes, 0xFF)?,
                    });
                }
                _ => {
                    let raw = i128::from(d.int()?);
                    let abs = if first { raw } else { previous + raw };
                    previous = abs;
                    first = false;
                    let (bytes, unused_bits) = framed_from_absolute_int(abs)?;
                    entries.push(IpAddressOrRange::Prefix(build_prefix(afi, &bytes, unused_bits)?));
                }
            }
        } else {
            match d.datatype()? {
                Type::Array | Type::ArrayIndef => {
                    let n = crate::common::definite_array_len(d)?;
                    if n != 2 {
                        return Err(Error::malformed("AddressRange must have 2 elements"));
                    }
                    let min_raw = d.bytes()?;
                    if min_raw.is_empty() {
                        return Err(Error::malformed("empty RFC 3779 address byte string"));
                    }
                    let min = build_addr(afi, &min_raw[1..], 0x00)?;
                    let max_raw = d.bytes()?;
                    if max_raw.is_empty() {
                        return Err(Error::malformed("empty RFC 3779 address byte string"));
                    }
                    let max = build_addr(afi, &max_raw[1..], 0xFF)?;
                    entries.push(IpAddressOrRange::Range { min, max });
                }
                _ => {
                    let raw = d.bytes()?;
                    if raw.is_empty() {
                        return Err(Error::malformed("empty RFC 3779 address byte string"));
                    }
                    let net = build_prefix(afi, &raw[1..], raw[0])?;
                    entries.push(IpAddressOrRange::Prefix(net));
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

/// A `Prefix` or `Range` entry, reduced to plain `(significant bytes,
/// unusedBits)` pairs ready for either the delta-coded int form or the raw
/// bytes form.
enum ResolvedEntry {
    Prefix { bytes: Vec<u8>, unused_bits: u8 },
    Range { min_bytes: Vec<u8>, max_bytes: Vec<u8> },
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
            let resolved: Vec<ResolvedEntry> = entries
                .iter()
                .map(|entry| match entry {
                    IpAddressOrRange::Prefix(net) => {
                        let (bytes, unused_bits) = prefix_to_framed(net);
                        ResolvedEntry::Prefix { bytes, unused_bits }
                    }
                    IpAddressOrRange::Range { min, max } => ResolvedEntry::Range {
                        min_bytes: addr_to_framed_trimmed(min, 0x00),
                        max_bytes: addr_to_framed_trimmed(max, 0xFF),
                    },
                })
                .collect();

            let use_int_form = resolved.iter().all(|r| match r {
                ResolvedEntry::Prefix { bytes, .. } => bytes.len() < MAX_INT_FORM_BYTES,
                ResolvedEntry::Range { min_bytes, max_bytes } => {
                    min_bytes.len() < MAX_INT_FORM_BYTES && max_bytes.len() < MAX_INT_FORM_BYTES
                }
            });

            e.array(entries.len() as u64)?;
            if use_int_form {
                let mut previous: i128 = 0;
                let mut first = true;
                for r in &resolved {
                    match r {
                        ResolvedEntry::Prefix { bytes, unused_bits } => {
                            let abs = absolute_int_from_framed(bytes, *unused_bits).map_err(to_encode_err::<W>)?;
                            let delta = if first { abs } else { abs - previous };
                            previous = abs;
                            first = false;
                            encode_delta(e, delta)?;
                        }
                        ResolvedEntry::Range { min_bytes, max_bytes } => {
                            let min_abs = absolute_int_from_framed(min_bytes, 0).map_err(to_encode_err::<W>)?;
                            let min_delta = if first { min_abs } else { min_abs - previous };
                            previous = min_abs;
                            first = false;
                            let max_abs = absolute_int_from_framed(max_bytes, 0).map_err(to_encode_err::<W>)?;
                            let max_delta = max_abs - previous;
                            previous = max_abs;
                            e.array(2)?;
                            encode_delta(e, min_delta)?;
                            encode_delta(e, max_delta)?;
                        }
                    }
                }
            } else {
                for r in &resolved {
                    match r {
                        ResolvedEntry::Prefix { bytes, unused_bits } => {
                            let mut raw = Vec::with_capacity(bytes.len() + 1);
                            raw.push(*unused_bits);
                            raw.extend_from_slice(bytes);
                            e.bytes(&raw)?;
                        }
                        ResolvedEntry::Range { min_bytes, max_bytes } => {
                            e.array(2)?;
                            let mut min_raw = Vec::with_capacity(min_bytes.len() + 1);
                            min_raw.push(0);
                            min_raw.extend_from_slice(min_bytes);
                            e.bytes(&min_raw)?;
                            let mut max_raw = Vec::with_capacity(max_bytes.len() + 1);
                            max_raw.push(0);
                            max_raw.extend_from_slice(max_bytes);
                            e.bytes(&max_raw)?;
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
