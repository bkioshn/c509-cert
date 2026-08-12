//! X.509 extension encoding (Section 3.1.10 / Section 3.3).
//!
//! ```text
//! Extensions = [ * Extension ] / int
//!
//! Extension = (
//!     ( extensionID: int, extensionValue: Defined ) //
//!     ( extensionID: ~oid, extensionValue: bytes / [ bytes ] )
//! )
//! ```
//!
//! Every extension listed in Section 3.3 gets a typed [`ExtensionValue`]
//! variant; anything else (an unrecognized int `extensionID`, or any
//! `~oid`-identified extension) is kept as [`ExtensionValue::Raw`] — the
//! undecoded DER `extnValue` bytes for the oid form, or the raw CBOR item
//! bytes for an unrecognized int form.

pub mod ip_addr;

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::common::{self, IntOrOid, SpecialText};
use crate::error::{Error, Result};
use crate::name::Name;
use crate::oid::Oid;
use ip_addr::{AsIdOrRange, IpAddressFamily};

fn expect_array_len(d: &mut Decoder<'_>, want: u64) -> Result<()> {
    let len = common::definite_array_len(d)?;
    if len != want {
        return Err(Error::malformed("unexpected array length"));
    }
    Ok(())
}

fn decode_opt_uint(d: &mut Decoder<'_>) -> Result<Option<u32>> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        Ok(Some(d.u32()?))
    }
}

fn encode_opt_uint<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
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

// ============================= GeneralName ==============================

/// Section 8.13 "C509 General Names Registry".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeneralNameValue {
    /// `otherName` (registry value 0): `[ ~oid, bytes ]`.
    OtherName { type_id: Oid, value: Vec<u8> },
    /// `otherName` with `id-on-hardwareModuleName` (registry value -1).
    HardwareModuleName { hw_type: Oid, hw_serial_num: Vec<u8> },
    /// `otherName` with `id-on-SmtpUTF8Mailbox` (registry value -2).
    SmtpUtf8Mailbox(String),
    /// `otherName` with `id-on-MACAddress` (registry value -3).
    MacAddress(Vec<u8>),
    Rfc822Name(String),
    DnsName(String),
    DirectoryName(Name),
    Uri(String),
    IpAddress(Vec<u8>),
    RegisteredId(Oid),
    /// A `GeneralNameType` this crate does not decode; the raw CBOR item.
    Raw(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralName {
    pub kind: i32,
    pub value: GeneralNameValue,
}

impl GeneralName {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let kind = d.i32()?;
        let value = match kind {
            -3 => GeneralNameValue::MacAddress(d.bytes()?.to_vec()),
            -2 => GeneralNameValue::SmtpUtf8Mailbox(d.str()?.to_string()),
            -1 => {
                expect_array_len(d, 2)?;
                let hw_type = Oid::new(d.bytes()?.to_vec());
                let hw_serial_num = d.bytes()?.to_vec();
                GeneralNameValue::HardwareModuleName { hw_type, hw_serial_num }
            }
            0 => {
                expect_array_len(d, 2)?;
                let type_id = Oid::new(d.bytes()?.to_vec());
                let value = d.bytes()?.to_vec();
                GeneralNameValue::OtherName { type_id, value }
            }
            1 => GeneralNameValue::Rfc822Name(d.str()?.to_string()),
            2 => GeneralNameValue::DnsName(d.str()?.to_string()),
            4 => GeneralNameValue::DirectoryName(Name::decode(d)?),
            6 => GeneralNameValue::Uri(d.str()?.to_string()),
            7 => GeneralNameValue::IpAddress(d.bytes()?.to_vec()),
            8 => GeneralNameValue::RegisteredId(Oid::new(d.bytes()?.to_vec())),
            _ => GeneralNameValue::Raw(common::raw_item(d)?),
        };
        Ok(GeneralName { kind, value })
    }

    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.i32(self.kind)?;
        match &self.value {
            GeneralNameValue::MacAddress(b) => {
                e.bytes(b)?;
            }
            GeneralNameValue::SmtpUtf8Mailbox(s) => {
                e.str(s)?;
            }
            GeneralNameValue::HardwareModuleName {
                hw_type,
                hw_serial_num,
            } => {
                e.array(2)?;
                e.bytes(hw_type.as_bytes())?;
                e.bytes(hw_serial_num)?;
            }
            GeneralNameValue::OtherName { type_id, value } => {
                e.array(2)?;
                e.bytes(type_id.as_bytes())?;
                e.bytes(value)?;
            }
            GeneralNameValue::Rfc822Name(s) | GeneralNameValue::DnsName(s) | GeneralNameValue::Uri(s) => {
                e.str(s)?;
            }
            GeneralNameValue::DirectoryName(n) => {
                n.encode(e)?;
            }
            GeneralNameValue::IpAddress(b) => {
                e.bytes(b)?;
            }
            GeneralNameValue::RegisteredId(oid) => {
                e.bytes(oid.as_bytes())?;
            }
            GeneralNameValue::Raw(bytes) => {
                common::write_raw(e, bytes)?;
            }
        }
        Ok(())
    }
}

fn decode_general_names(d: &mut Decoder<'_>) -> Result<Vec<GeneralName>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed("GeneralNames array must have an even number of elements"));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        out.push(GeneralName::decode(d)?);
    }
    Ok(out)
}

fn encode_general_names<W: minicbor::encode::Write>(
    names: &[GeneralName],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(names.len() as u64 * 2)?;
    for n in names {
        n.encode(e)?;
    }
    Ok(())
}

/// `SubjectAltName = GeneralNames / text` (and identically `IssuerAltName`):
/// a lone `dNSName` collapses to a bare CBOR text string.
fn decode_alt_name(d: &mut Decoder<'_>) -> Result<Vec<GeneralName>> {
    match d.datatype()? {
        Type::String => {
            let s = d.str()?.to_string();
            Ok(vec![GeneralName {
                kind: 2,
                value: GeneralNameValue::DnsName(s),
            }])
        }
        _ => decode_general_names(d),
    }
}

fn encode_alt_name<W: minicbor::encode::Write>(
    names: &[GeneralName],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    if names.len() == 1
        && let GeneralName {
            kind: 2,
            value: GeneralNameValue::DnsName(s),
        } = &names[0]
        {
            e.str(s)?;
            return Ok(());
        }
    encode_general_names(names, e)
}

// =========================== BasicConstraints ============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasicConstraints {
    NotCa,
    Ca { path_len: Option<u32> },
}

impl BasicConstraints {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let v = d.i32()?;
        match v {
            -2 => Ok(BasicConstraints::NotCa),
            -1 => Ok(BasicConstraints::Ca { path_len: None }),
            n if n >= 0 => Ok(BasicConstraints::Ca {
                path_len: Some(n as u32),
            }),
            _ => Err(Error::malformed("invalid basicConstraints value")),
        }
    }

    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            BasicConstraints::NotCa => {
                e.i32(-2)?;
            }
            BasicConstraints::Ca { path_len: None } => {
                e.i32(-1)?;
            }
            BasicConstraints::Ca { path_len: Some(n) } => {
                e.i32(*n as i32)?;
            }
        }
        Ok(())
    }
}

// =========================== PolicyConstraints ============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConstraints {
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

impl PolicyConstraints {
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        expect_array_len(d, 2)?;
        let require_explicit_policy = decode_opt_uint(d)?;
        let inhibit_policy_mapping = decode_opt_uint(d)?;
        Ok(Self {
            require_explicit_policy,
            inhibit_policy_mapping,
        })
    }

    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;
        encode_opt_uint(e, self.require_explicit_policy)?;
        encode_opt_uint(e, self.inhibit_policy_mapping)?;
        Ok(())
    }
}

// ========================= DistributionPointName ==========================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionPointName {
    pub full_name: Vec<String>,
    pub reasons: Option<u32>,
    pub crl_issuer: Option<Name>,
}

fn decode_distribution_point_name(d: &mut Decoder<'_>) -> Result<DistributionPointName> {
    expect_array_len(d, 3)?;
    let full_name = match d.datatype()? {
        Type::String => vec![d.str()?.to_string()],
        _ => {
            let n = common::definite_array_len(d)?;
            let mut v = Vec::with_capacity(n as usize);
            for _ in 0..n {
                v.push(d.str()?.to_string());
            }
            v
        }
    };
    let reasons = decode_opt_uint(d)?;
    let crl_issuer = Name::decode_optional(d)?;
    Ok(DistributionPointName {
        full_name,
        reasons,
        crl_issuer,
    })
}

fn encode_distribution_point_name<W: minicbor::encode::Write>(
    dp: &DistributionPointName,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(3)?;
    match dp.full_name.as_slice() {
        [single] => {
            e.str(single)?;
        }
        many => {
            e.array(many.len() as u64)?;
            for s in many {
                e.str(s)?;
            }
        }
    }
    encode_opt_uint(e, dp.reasons)?;
    Name::encode_optional(&dp.crl_issuer, e)?;
    Ok(())
}

/// `CRLDistributionPoints = [ + DistributionPointName ] / text` (and
/// identically `FreshestCRL`): a single distribution point whose only field
/// is a lone URI collapses to a bare CBOR text string.
fn decode_distribution_points(d: &mut Decoder<'_>) -> Result<Vec<DistributionPointName>> {
    match d.datatype()? {
        Type::String => {
            let s = d.str()?.to_string();
            Ok(vec![DistributionPointName {
                full_name: vec![s],
                reasons: None,
                crl_issuer: None,
            }])
        }
        _ => {
            let len = common::definite_array_len(d)?;
            let mut out = Vec::with_capacity(len as usize);
            for _ in 0..len {
                out.push(decode_distribution_point_name(d)?);
            }
            Ok(out)
        }
    }
}

fn encode_distribution_points<W: minicbor::encode::Write>(
    points: &[DistributionPointName],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    if points.len() == 1 {
        let dp = &points[0];
        if dp.full_name.len() == 1 && dp.reasons.is_none() && dp.crl_issuer.is_none() {
            e.str(&dp.full_name[0])?;
            return Ok(());
        }
    }
    e.array(points.len() as u64)?;
    for dp in points {
        encode_distribution_point_name(dp, e)?;
    }
    Ok(())
}

// =========================== AccessDescription =============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDescription {
    pub access_method: IntOrOid,
    pub uri: String,
}

fn decode_access_descriptions(d: &mut Decoder<'_>) -> Result<Vec<AccessDescription>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed("AccessDescription array must have an even number of elements"));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        let access_method = IntOrOid::decode(d)?;
        let uri = d.str()?.to_string();
        out.push(AccessDescription { access_method, uri });
    }
    Ok(out)
}

fn encode_access_descriptions<W: minicbor::encode::Write>(
    v: &[AccessDescription],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(v.len() as u64 * 2)?;
    for ad in v {
        ad.access_method.encode(e)?;
        e.str(&ad.uri)?;
    }
    Ok(())
}

// ========================= AuthorityKeyIdentifier ==========================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKeyIdentifier {
    pub key_identifier: Vec<u8>,
    pub cert_issuer: Option<Vec<GeneralName>>,
    pub cert_serial: Option<Vec<u8>>,
}

fn decode_authority_key_identifier(d: &mut Decoder<'_>) -> Result<AuthorityKeyIdentifier> {
    match d.datatype()? {
        Type::Bytes => Ok(AuthorityKeyIdentifier {
            key_identifier: d.bytes()?.to_vec(),
            cert_issuer: None,
            cert_serial: None,
        }),
        _ => {
            expect_array_len(d, 3)?;
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

fn encode_authority_key_identifier<W: minicbor::encode::Write>(
    v: &AuthorityKeyIdentifier,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match (&v.cert_issuer, &v.cert_serial) {
        (None, None) => {
            e.bytes(&v.key_identifier)?;
        }
        (Some(issuer), Some(serial)) => {
            e.array(3)?;
            e.bytes(&v.key_identifier)?;
            encode_general_names(issuer, e)?;
            e.bytes(serial)?;
        }
        _ => {
            return Err(minicbor::encode::Error::message(
                "AuthorityKeyIdentifier requires both cert_issuer and cert_serial, or neither",
            ))
        }
    }
    Ok(())
}

// ============================ CertificatePolicies ===========================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyQualifier {
    pub id: IntOrOid,
    pub qualifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInformation {
    pub id: IntOrOid,
    pub qualifiers: Vec<PolicyQualifier>,
}

fn decode_certificate_policies(d: &mut Decoder<'_>) -> Result<Vec<PolicyInformation>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed("CertificatePolicies array must have an even number of elements"));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        let id = IntOrOid::decode(d)?;
        let qlen = common::definite_array_len(d)?;
        if qlen % 2 != 0 {
            return Err(Error::malformed("PolicyQualifierInfo array must have an even number of elements"));
        }
        let mut qualifiers = Vec::with_capacity((qlen / 2) as usize);
        for _ in 0..(qlen / 2) {
            let qid = IntOrOid::decode(d)?;
            let qualifier = d.str()?.to_string();
            qualifiers.push(PolicyQualifier { id: qid, qualifier });
        }
        out.push(PolicyInformation { id, qualifiers });
    }
    Ok(out)
}

fn encode_certificate_policies<W: minicbor::encode::Write>(
    v: &[PolicyInformation],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(v.len() as u64 * 2)?;
    for pi in v {
        pi.id.encode(e)?;
        e.array(pi.qualifiers.len() as u64 * 2)?;
        for q in &pi.qualifiers {
            q.id.encode(e)?;
            e.str(&q.qualifier)?;
        }
    }
    Ok(())
}

// ============================= NameConstraints ==============================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameConstraints {
    pub permitted: Option<Vec<GeneralName>>,
    pub excluded: Option<Vec<GeneralName>>,
}

fn decode_opt_general_subtree(d: &mut Decoder<'_>) -> Result<Option<Vec<GeneralName>>> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        Ok(Some(decode_general_names(d)?))
    }
}

fn encode_opt_general_subtree<W: minicbor::encode::Write>(
    v: &Option<Vec<GeneralName>>,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match v {
        Some(names) => encode_general_names(names, e)?,
        None => {
            e.null()?;
        }
    }
    Ok(())
}

fn decode_name_constraints(d: &mut Decoder<'_>) -> Result<NameConstraints> {
    expect_array_len(d, 2)?;
    let permitted = decode_opt_general_subtree(d)?;
    let excluded = decode_opt_general_subtree(d)?;
    Ok(NameConstraints { permitted, excluded })
}

fn encode_name_constraints<W: minicbor::encode::Write>(
    v: &NameConstraints,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(2)?;
    encode_opt_general_subtree(&v.permitted, e)?;
    encode_opt_general_subtree(&v.excluded, e)?;
    Ok(())
}

// ============================== PolicyMappings ================================

fn decode_policy_mappings(d: &mut Decoder<'_>) -> Result<Vec<(IntOrOid, IntOrOid)>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed("PolicyMappings array must have an even number of elements"));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        let issuer_domain_policy = IntOrOid::decode(d)?;
        let subject_domain_policy = IntOrOid::decode(d)?;
        out.push((issuer_domain_policy, subject_domain_policy));
    }
    Ok(out)
}

fn encode_policy_mappings<W: minicbor::encode::Write>(
    v: &[(IntOrOid, IntOrOid)],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(v.len() as u64 * 2)?;
    for (a, b) in v {
        a.encode(e)?;
        b.encode(e)?;
    }
    Ok(())
}

// ============================== ExtKeyUsageSyntax =============================

/// `ExtKeyUsageSyntax = [ 2* KeyPurposeId ] / KeyPurposeId`: a single key
/// purpose collapses to a bare `KeyPurposeId`.
fn decode_ext_key_usage(d: &mut Decoder<'_>) -> Result<Vec<IntOrOid>> {
    match d.datatype()? {
        Type::Array | Type::ArrayIndef => Ok(d.decode()?),
        _ => Ok(vec![IntOrOid::decode(d)?]),
    }
}

fn encode_ext_key_usage<W: minicbor::encode::Write>(
    v: &[IntOrOid],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    if let [single] = v {
        single.encode(e)?;
        return Ok(());
    }
    e.array(v.len() as u64)?;
    for item in v {
        item.encode(e)?;
    }
    Ok(())
}

// ====================== SubjectDirectoryAttributes ========================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdnAttributeMulti {
    Registered {
        id: u16,
        printable_string: bool,
        values: Vec<SpecialText>,
    },
    Oid {
        oid: Oid,
        values: Vec<Vec<u8>>,
    },
}

fn decode_subject_directory_attributes(d: &mut Decoder<'_>) -> Result<Vec<RdnAttributeMulti>> {
    let len = common::definite_array_len(d)?;
    if len % 2 != 0 {
        return Err(Error::malformed(
            "SubjectDirectoryAttributes array must have an even number of elements",
        ));
    }
    let mut out = Vec::with_capacity((len / 2) as usize);
    for _ in 0..(len / 2) {
        match d.datatype()? {
            Type::Bytes => {
                let oid = Oid::new(d.bytes()?.to_vec());
                let n = common::definite_array_len(d)?;
                let mut values = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    values.push(d.bytes()?.to_vec());
                }
                out.push(RdnAttributeMulti::Oid { oid, values });
            }
            _ => {
                let raw = d.i32()?;
                let printable_string = raw < 0;
                let id = raw.unsigned_abs() as u16;
                let n = common::definite_array_len(d)?;
                let mut values = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    values.push(SpecialText::decode(d)?);
                }
                out.push(RdnAttributeMulti::Registered {
                    id,
                    printable_string,
                    values,
                });
            }
        }
    }
    Ok(out)
}

fn encode_subject_directory_attributes<W: minicbor::encode::Write>(
    v: &[RdnAttributeMulti],
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    e.array(v.len() as u64 * 2)?;
    for attr in v {
        match attr {
            RdnAttributeMulti::Registered {
                id,
                printable_string,
                values,
            } => {
                let raw = if *printable_string { -(*id as i32) } else { *id as i32 };
                e.i32(raw)?;
                e.array(values.len() as u64)?;
                for val in values {
                    val.encode(e)?;
                }
            }
            RdnAttributeMulti::Oid { oid, values } => {
                e.bytes(oid.as_bytes())?;
                e.array(values.len() as u64)?;
                for val in values {
                    e.bytes(val)?;
                }
            }
        }
    }
    Ok(())
}

// =============================== ExtensionValue ================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionValue {
    /// id 1
    SubjectKeyIdentifier(Vec<u8>),
    /// id 2 — `KeyUsage` BIT STRING interpreted as an unsigned int (network
    /// byte order).
    KeyUsage(u32),
    /// id 3
    SubjectAltName(Vec<GeneralName>),
    /// id 4
    BasicConstraints(BasicConstraints),
    /// id 5
    CrlDistributionPoints(Vec<DistributionPointName>),
    /// id 6
    CertificatePolicies(Vec<PolicyInformation>),
    /// id 7
    AuthorityKeyIdentifier(AuthorityKeyIdentifier),
    /// id 8
    ExtKeyUsage(Vec<IntOrOid>),
    /// id 9
    AuthorityInfoAccess(Vec<AccessDescription>),
    /// id 24
    SubjectDirectoryAttributes(Vec<RdnAttributeMulti>),
    /// id 25
    IssuerAltName(Vec<GeneralName>),
    /// id 26
    NameConstraints(NameConstraints),
    /// id 27
    PolicyMappings(Vec<(IntOrOid, IntOrOid)>),
    /// id 28
    PolicyConstraints(PolicyConstraints),
    /// id 29
    FreshestCrl(Vec<DistributionPointName>),
    /// id 30
    InhibitAnyPolicy(u32),
    /// id 31
    SubjectInfoAccess(Vec<AccessDescription>),
    /// id 32 (`id-pe-ipAddrBlocks`, RFC 3779)
    IpAddrBlocks(Vec<IpAddressFamily>),
    /// id 33 (`id-pe-autonomousSysIds`, RFC 3779)
    AsIdentifiers(Option<Vec<AsIdOrRange>>),
    /// id 34 (`id-pe-ipAddrBlocks-v2`, RFC 8360)
    IpAddrBlocksV2(Vec<IpAddressFamily>),
    /// id 35 (`id-pe-autonomousSysIds-v2`, RFC 8360)
    AsIdentifiersV2(Option<Vec<AsIdOrRange>>),
    /// id 36 (`id-pkix-ocsp-nocheck`)
    OcspNoCheck,
    /// id 38 (`id-pe-tlsfeature`)
    TlsFeatures(Vec<u32>),
    /// Any int `extensionID` not special-cased above, or any `~oid`
    /// extension: the raw undecoded value (DER `extnValue` bytes for the
    /// oid form, raw CBOR item bytes for the int form).
    Raw(Vec<u8>),
}

fn decode_extension_value(id: u32, d: &mut Decoder<'_>) -> Result<ExtensionValue> {
    Ok(match id {
        1 => ExtensionValue::SubjectKeyIdentifier(d.bytes()?.to_vec()),
        2 => ExtensionValue::KeyUsage(d.u32()?),
        3 => ExtensionValue::SubjectAltName(decode_alt_name(d)?),
        4 => ExtensionValue::BasicConstraints(BasicConstraints::decode(d)?),
        5 => ExtensionValue::CrlDistributionPoints(decode_distribution_points(d)?),
        6 => ExtensionValue::CertificatePolicies(decode_certificate_policies(d)?),
        7 => ExtensionValue::AuthorityKeyIdentifier(decode_authority_key_identifier(d)?),
        8 => ExtensionValue::ExtKeyUsage(decode_ext_key_usage(d)?),
        9 => ExtensionValue::AuthorityInfoAccess(decode_access_descriptions(d)?),
        24 => ExtensionValue::SubjectDirectoryAttributes(decode_subject_directory_attributes(d)?),
        25 => ExtensionValue::IssuerAltName(decode_alt_name(d)?),
        26 => ExtensionValue::NameConstraints(decode_name_constraints(d)?),
        27 => ExtensionValue::PolicyMappings(decode_policy_mappings(d)?),
        28 => ExtensionValue::PolicyConstraints(PolicyConstraints::decode(d)?),
        29 => ExtensionValue::FreshestCrl(decode_distribution_points(d)?),
        30 => ExtensionValue::InhibitAnyPolicy(d.u32()?),
        31 => ExtensionValue::SubjectInfoAccess(decode_access_descriptions(d)?),
        32 => ExtensionValue::IpAddrBlocks(ip_addr::decode_ip_address_families(d)?),
        33 => ExtensionValue::AsIdentifiers(ip_addr::decode_as_identifiers(d)?),
        34 => ExtensionValue::IpAddrBlocksV2(ip_addr::decode_ip_address_families(d)?),
        35 => ExtensionValue::AsIdentifiersV2(ip_addr::decode_as_identifiers(d)?),
        36 => {
            d.null()?;
            ExtensionValue::OcspNoCheck
        }
        38 => ExtensionValue::TlsFeatures(d.decode()?),
        _ => ExtensionValue::Raw(common::raw_item(d)?),
    })
}

fn encode_extension_value<W: minicbor::encode::Write>(
    value: &ExtensionValue,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match value {
        ExtensionValue::SubjectKeyIdentifier(b) => {
            e.bytes(b)?;
        }
        ExtensionValue::KeyUsage(n) => {
            e.u32(*n)?;
        }
        ExtensionValue::SubjectAltName(names) | ExtensionValue::IssuerAltName(names) => {
            encode_alt_name(names, e)?;
        }
        ExtensionValue::BasicConstraints(bc) => bc.encode(e)?,
        ExtensionValue::CrlDistributionPoints(dp) | ExtensionValue::FreshestCrl(dp) => {
            encode_distribution_points(dp, e)?;
        }
        ExtensionValue::CertificatePolicies(v) => encode_certificate_policies(v, e)?,
        ExtensionValue::AuthorityKeyIdentifier(v) => encode_authority_key_identifier(v, e)?,
        ExtensionValue::ExtKeyUsage(v) => encode_ext_key_usage(v, e)?,
        ExtensionValue::AuthorityInfoAccess(v) | ExtensionValue::SubjectInfoAccess(v) => {
            encode_access_descriptions(v, e)?;
        }
        ExtensionValue::SubjectDirectoryAttributes(v) => encode_subject_directory_attributes(v, e)?,
        ExtensionValue::NameConstraints(v) => encode_name_constraints(v, e)?,
        ExtensionValue::PolicyMappings(v) => encode_policy_mappings(v, e)?,
        ExtensionValue::PolicyConstraints(v) => v.encode(e)?,
        ExtensionValue::InhibitAnyPolicy(n) => {
            e.u32(*n)?;
        }
        ExtensionValue::IpAddrBlocks(v) | ExtensionValue::IpAddrBlocksV2(v) => {
            ip_addr::encode_ip_address_families(v, e)?;
        }
        ExtensionValue::AsIdentifiers(v) | ExtensionValue::AsIdentifiersV2(v) => {
            ip_addr::encode_as_identifiers(v, e)?;
        }
        ExtensionValue::OcspNoCheck => {
            e.null()?;
        }
        ExtensionValue::TlsFeatures(v) => {
            e.encode(v)?;
        }
        ExtensionValue::Raw(bytes) => common::write_raw(e, bytes)?,
    }
    Ok(())
}

// ================================= Extension ===================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The registry id (Section 8.8) or OID of this extension. Note the
    /// criticality *sign* used on the wire is not folded in here; see
    /// [`Extension::critical`].
    pub id: IntOrOid,
    pub critical: bool,
    pub value: ExtensionValue,
}

fn decode_extension(d: &mut Decoder<'_>) -> Result<Extension> {
    match d.datatype()? {
        Type::Bytes => {
            let oid = Oid::new(d.bytes()?.to_vec());
            let (critical, raw) = match d.datatype()? {
                Type::Array | Type::ArrayIndef => {
                    expect_array_len(d, 1)?;
                    (true, d.bytes()?.to_vec())
                }
                _ => (false, d.bytes()?.to_vec()),
            };
            Ok(Extension {
                id: IntOrOid::Oid(oid),
                critical,
                value: ExtensionValue::Raw(raw),
            })
        }
        _ => {
            let raw_id = d.i32()?;
            let critical = raw_id < 0;
            let id = raw_id.unsigned_abs();
            let value = decode_extension_value(id, d)?;
            Ok(Extension {
                id: IntOrOid::Int(id as i32),
                critical,
                value,
            })
        }
    }
}

fn encode_extension<W: minicbor::encode::Write>(
    ext: &Extension,
    e: &mut Encoder<W>,
) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
    match &ext.id {
        IntOrOid::Int(id) => {
            let signed = if ext.critical { -(*id) } else { *id };
            e.i32(signed)?;
            encode_extension_value(&ext.value, e)?;
        }
        IntOrOid::Oid(oid) => {
            e.bytes(oid.as_bytes())?;
            let raw = match &ext.value {
                ExtensionValue::Raw(b) => b.as_slice(),
                _ => {
                    return Err(minicbor::encode::Error::message(
                        "oid-identified extensions must use ExtensionValue::Raw",
                    ))
                }
            };
            if ext.critical {
                e.array(1)?;
                e.bytes(raw)?;
            } else {
                e.bytes(raw)?;
            }
        }
    }
    Ok(())
}

// ================================= Extensions ===================================

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions(pub Vec<Extension>);

impl Extensions {
    pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        match d.datatype()? {
            Type::Array | Type::ArrayIndef => {
                let len = common::definite_array_len(d)?;
                if len % 2 != 0 {
                    return Err(Error::malformed("Extensions array must have an even number of elements"));
                }
                let mut out = Vec::with_capacity((len / 2) as usize);
                for _ in 0..(len / 2) {
                    out.push(decode_extension(d)?);
                }
                Ok(Extensions(out))
            }
            // Compact single-extension shortcut, only defined for keyUsage
            // (registry id 2): sign = criticality, absolute value = the
            // KeyUsage bitmask.
            _ => {
                let raw = d.i32()?;
                let critical = raw < 0;
                let value = raw.unsigned_abs();
                Ok(Extensions(vec![Extension {
                    id: IntOrOid::Int(2),
                    critical,
                    value: ExtensionValue::KeyUsage(value),
                }]))
            }
        }
    }

    pub(crate) fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
    ) -> core::result::Result<(), minicbor::encode::Error<W::Error>> {
        if self.0.len() == 1
            && let Extension {
                id: IntOrOid::Int(2),
                critical,
                value: ExtensionValue::KeyUsage(v),
            } = &self.0[0]
            {
                let signed = if *critical { -(*v as i32) } else { *v as i32 };
                e.i32(signed)?;
                return Ok(());
            }
        e.array(self.0.len() as u64 * 2)?;
        for ext in &self.0 {
            encode_extension(ext, e)?;
        }
        Ok(())
    }
}
