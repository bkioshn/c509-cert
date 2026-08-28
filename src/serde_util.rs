//! `serde` helpers bridging wire types that don't already have a natural
//! JSON shape onto plain strings, so `serde_json::to_string`/`from_str` work
//! directly on [`crate::C509Certificate`]. This is a separate, more
//! permissive mirror than [`crate::cert_json`]'s hand-authored `from_json`
//! schema (which only understands a handful of extension kinds); the two
//! happen to agree on hex/RFC 3339 string conventions, but round-tripping
//! through one isn't guaranteed to match the other's input shape.

use core::fmt::Display;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serializer};

/// Shared `Option<T>` plumbing for the string-based codecs below: `Some`
/// serializes via `to_str`, `None` as JSON `null`.
fn serialize_opt_str<T, S: Serializer>(
    v: &Option<T>,
    to_str: impl FnOnce(&T) -> Result<String, S::Error>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_str(&to_str(v)?),
        None => s.serialize_none(),
    }
}

/// Inverse of [`serialize_opt_str`]: `null` deserializes to `None`, a string
/// is parsed via `parse`.
fn deserialize_opt_str<'de, T, E, D>(
    d: D,
    parse: impl FnOnce(&str) -> Result<T, E>,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    E: Display,
{
    Option::<String>::deserialize(d)?
        .map(|s| parse(&s).map_err(serde::de::Error::custom))
        .transpose()
}

/// Serialize/deserialize any [`Display`] + [`FromStr`] type (e.g.
/// [`macaddr::MacAddr`], [`ipnet::IpNet`]) via its string form.
pub(crate) mod display_str {
    use super::{Deserialize, Deserializer, Display, FromStr, Serializer};

    pub(crate) fn serialize<T: Display, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(v)
    }

    pub(crate) fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        T::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Serialize/deserialize an [`oid::ObjectIdentifier`] via its dotted string form.
pub(crate) mod oid_str {
    use oid::ObjectIdentifier;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &ObjectIdentifier, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&String::from(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<ObjectIdentifier, D::Error> {
        let s = String::deserialize(d)?;
        // `ObjectIdentifierError` doesn't implement `Display`, only `Debug`.
        ObjectIdentifier::try_from(s.as_str())
            .map_err(|e| serde::de::Error::custom(format!("invalid OID: {e:?}")))
    }
}

/// Serialize/deserialize raw bytes as a lowercase hex string.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn serialize_opt<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        super::serialize_opt_str(bytes, |b| Ok(hex::encode(b)), s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }

    pub(crate) fn deserialize_opt<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        super::deserialize_opt_str(d, |s| hex::decode(s))
    }
}

/// Serialize/deserialize a [`num_bigint::BigUint`] as a big-endian hex
/// string, matching [`crate::cert_json`]'s convention for serial numbers.
pub(crate) mod biguint_hex {
    use num_bigint::BigUint;
    use serde::{Deserialize, Deserializer, Serializer};

    fn parse(s: &str) -> Result<BigUint, hex::FromHexError> {
        hex::decode(s).map(|bytes| BigUint::from_bytes_be(&bytes))
    }

    pub(crate) fn serialize<S: Serializer>(n: &BigUint, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(n.to_bytes_be()))
    }

    pub(crate) fn serialize_opt<S: Serializer>(
        n: &Option<BigUint>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        super::serialize_opt_str(n, |n| Ok(hex::encode(n.to_bytes_be())), s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BigUint, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s).map_err(serde::de::Error::custom)
    }

    pub(crate) fn deserialize_opt<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<BigUint>, D::Error> {
        super::deserialize_opt_str(d, parse)
    }
}

/// Serialize/deserialize a [`time::OffsetDateTime`] as an RFC 3339 string,
/// matching [`crate::cert_json`]'s convention for validity dates.
pub(crate) mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    pub(crate) fn serialize<S: Serializer>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        let text = dt.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
        s.serialize_str(&text)
    }

    pub(crate) fn serialize_opt<S: Serializer>(
        dt: &Option<OffsetDateTime>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        super::serialize_opt_str(
            dt,
            |dt| dt.format(&Rfc3339).map_err(serde::ser::Error::custom),
            s,
        )
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let s = String::deserialize(d)?;
        OffsetDateTime::parse(&s, &Rfc3339).map_err(serde::de::Error::custom)
    }

    pub(crate) fn deserialize_opt<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<OffsetDateTime>, D::Error> {
        super::deserialize_opt_str(d, |s| OffsetDateTime::parse(s, &Rfc3339))
    }
}
