//! Round-trip tests built from the worked examples in
//! `draft-ietf-cose-cbor-encoded-cert-19` (Appendix A and Section 3.3.1).

use std::net::IpAddr;

use c509_cert::{
    AlgorithmIdentifier, C509Certificate, ExtKeyUsage, Extension, ExtensionValue, Extensions,
    IntOrOid, IpAddressChoice, IpAddressFamily, IpAddressOrRange, Name, RdnAttribute, SpecialText,
    TbsCertificate,
};
use ipnet::IpNet;
use macaddr::MacAddr;
use minicbor::Encoder;
use minicbor::data::Tag;
use num_bigint::BigUint;
use time::OffsetDateTime;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(s).expect("valid hex")
}

// Appendix A.1.1: "CBOR re-encoded X.509 v3 Certificate" (c509CertificateType
// = 3), 140-byte unwrapped ~C509Certificate CBOR Sequence.
const A1_1_DER_REENCODED: &str = "
    03
    43 01 F5 0D
    00
    6B 52 46 43 20 74 65 73 74 20 43 41
    1A 63 B0 CD 00
    1A 69 55 B9 00
    D8 30 46 01 23 45 67 89 AB
    01
    58 21 FE B1 21 6A B9 6E 5B 3B 33 40 F5 BD F0 2E 69 3F 16 21 3A 04 52
    5E D4 44 50 B1 01 9C 2D FD 38 38 AB
    01
    58 40 D4 32 0B 1D 68 49 E3 09 21 9D 30 03 7E 13 81 66 F2 50 82 47 DD
    DA E7 6C CE EA 55 05 3C 10 8E 90 D5 51 F6 D6 01 06 F1 AB B4 84 CF BE
    62 56 C1 78 E4 AC 33 14 EA 19 19 1E 8B 60 7D A5 AE 3B DA 16
";

// Appendix A.1.2: "Natively Signed C509 Certificate" (c509CertificateType =
// 2) corresponding to the same X.509 certificate.
const A1_2_NATIVE: &str = "
    02
    43 01 F5 0D
    00
    6B 52 46 43 20 74 65 73 74 20 43 41
    1A 63 B0 CD 00
    1A 69 55 B9 00
    D8 30 46 01 23 45 67 89 AB
    01
    58 21 02 B1 21 6A B9 6E 5B 3B 33 40 F5 BD F0 2E 69 3F 16 21 3A 04 52
    5E D4 44 50 B1 01 9C 2D FD 38 38 AB
    01
    58 40 EB 0D 47 27 31 F6 89 BC 00 F5 88 0B 12 C6 8B 3F 9F D3 8B 23 FA
    DF CA 20 95 0F 3F 24 1B 60 A2 02 57 9C AC 28 CD 3B 74 94 D5 FA 5D 8B
    BA B4 60 03 57 E5 50 AB 9F A9 A6 5D 9B A2 B3 B8 2E 66 8C C6
";

fn expect_compact_common_name(name: &Name, text: &str) {
    match name.0.as_slice() {
        [
            RdnAttribute::Registered {
                id: 1,
                printable_string: false,
                value: SpecialText::Text(s),
            },
        ] => assert_eq!(s, text),
        other => panic!("expected compact commonName {text:?}, got {other:?}"),
    }
}

#[test]
fn appendix_a1_1_der_reencoded_roundtrip() {
    let bytes = hex(A1_1_DER_REENCODED);
    assert_eq!(bytes.len(), 140);

    let cert = C509Certificate::decode_sequence(&bytes).expect("decode_sequence");
    assert_eq!(cert.tbs.c509_certificate_type, 3);
    assert_eq!(
        cert.tbs.certificate_serial_number,
        BigUint::from(128_269u32)
    );
    assert_eq!(
        cert.tbs.issuer_signature_algorithm,
        AlgorithmIdentifier::Int(0)
    );
    expect_compact_common_name(cert.tbs.issuer.as_ref().unwrap(), "RFC test CA");
    assert_eq!(
        cert.tbs.validity_not_before,
        OffsetDateTime::from_unix_timestamp(1_672_531_200).unwrap()
    );
    assert_eq!(
        cert.tbs.validity_not_after,
        Some(OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap())
    );

    match cert.tbs.subject.0.as_slice() {
        [
            RdnAttribute::Registered {
                id: 1,
                printable_string: false,
                value: SpecialText::Mac(mac),
            },
        ] => assert_eq!(*mac, MacAddr::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])),
        other => panic!("unexpected subject: {other:?}"),
    }

    assert_eq!(
        cert.tbs.subject_public_key_algorithm,
        AlgorithmIdentifier::Int(1)
    );
    assert_eq!(cert.tbs.subject_public_key.len(), 33);
    assert_eq!(
        cert.tbs.subject_public_key[0], 0xFE,
        "point-compressed, even y"
    );

    assert_eq!(cert.tbs.extensions.0.len(), 1);
    match &cert.tbs.extensions.0[0] {
        Extension {
            id: IntOrOid::Int(2),
            critical: false,
            value: ExtensionValue::KeyUsage(1),
        } => {}
        other => panic!("unexpected extension: {other:?}"),
    }

    assert_eq!(cert.issuer_signature_value.len(), 64);

    // Round trip: both the bare-sequence form and the wrapped-array form.
    assert_eq!(cert.encode_sequence(), bytes);
    let wrapped = cert.encode();
    assert_eq!(
        C509Certificate::decode(&wrapped).expect("decode wrapped"),
        cert
    );
}

#[test]
fn appendix_a1_2_natively_signed_roundtrip() {
    let bytes = hex(A1_2_NATIVE);
    assert_eq!(bytes.len(), 140);

    let cert = C509Certificate::decode_sequence(&bytes).expect("decode_sequence");
    assert_eq!(cert.tbs.c509_certificate_type, 2);
    assert_eq!(
        cert.tbs.certificate_serial_number,
        BigUint::from(128_269u32)
    );
    expect_compact_common_name(cert.tbs.issuer.as_ref().unwrap(), "RFC test CA");
    assert_eq!(cert.tbs.subject_public_key.len(), 33);
    assert_eq!(
        cert.tbs.subject_public_key[0], 0x02,
        "uncompressed-form octet, not point-compressed"
    );
    assert_eq!(cert.issuer_signature_value.len(), 64);

    assert_eq!(cert.encode_sequence(), bytes);
}

/// Builds a syntactically-valid 11-field `C509Certificate` (wrapped array
/// form) reusing the non-extension fields from Appendix A.1's example, with
/// a caller-supplied `extensions` CBOR item substituted in — used to drive
/// the extension decoder through the public API (its own `decode`/`encode`
/// methods are crate-private) with worked examples from the draft that
/// aren't full certificates.
fn build_cert_with_extensions(
    encode_extensions: impl FnOnce(&mut Encoder<&mut Vec<u8>>),
) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut e = Encoder::new(&mut buf);
        e.array(11).unwrap();
        e.i32(3).unwrap(); // c509CertificateType
        e.bytes(&hex("01F50D")).unwrap(); // certificateSerialNumber
        e.i32(0).unwrap(); // issuerSignatureAlgorithm
        e.str("RFC test CA").unwrap(); // issuer (compact commonName)
        e.u64(1_672_531_200).unwrap(); // validityNotBefore
        e.u64(1_767_225_600).unwrap(); // validityNotAfter
        e.tag(Tag::new(48))
            .unwrap()
            .bytes(&hex("0123456789AB"))
            .unwrap(); // subject
        e.i32(1).unwrap(); // subjectPublicKeyAlgorithm
        e.bytes(&hex("AABBCCDD")).unwrap(); // subjectPublicKey (dummy, opaque)
        encode_extensions(&mut e); // extensions
        e.bytes(&hex("D4320B1D")).unwrap(); // issuerSignatureValue (dummy, opaque)
    }
    buf
}

/// Section 3.3.1's worked example: `[ -4, -1, 2, 23, 8, [ 3, 9 ], 3,
/// "example.com" ]` — critical basicConstraints(cA=true, no pathLen),
/// non-critical keyUsage(23), non-critical extKeyUsage([codeSigning,
/// OCSPSigning]), non-critical subjectAltName(dNSName "example.com").
#[test]
fn section_3_3_1_extension_array_example() {
    let bytes = build_cert_with_extensions(|e| {
        e.array(8).unwrap();
        e.i32(-4).unwrap();
        e.i32(-1).unwrap();
        e.i32(2).unwrap();
        e.i32(23).unwrap();
        e.i32(8).unwrap();
        e.array(2).unwrap();
        e.i32(3).unwrap();
        e.i32(9).unwrap();
        e.i32(3).unwrap();
        e.str("example.com").unwrap();
    });

    let cert = C509Certificate::decode(&bytes).expect("decode");
    let exts = &cert.tbs.extensions.0;
    assert_eq!(exts.len(), 4);

    assert_eq!(exts[0].id, IntOrOid::Int(4));
    assert!(exts[0].critical);
    assert_eq!(
        exts[0].value,
        ExtensionValue::BasicConstraints(c509_cert::BasicConstraints::Ca { path_len: None })
    );

    assert_eq!(exts[1].id, IntOrOid::Int(2));
    assert!(!exts[1].critical);
    assert_eq!(exts[1].value, ExtensionValue::KeyUsage(23));

    assert_eq!(exts[2].id, IntOrOid::Int(8));
    assert!(!exts[2].critical);
    assert_eq!(
        exts[2].value,
        ExtensionValue::ExtKeyUsage(ExtKeyUsage(vec![IntOrOid::Int(3), IntOrOid::Int(9)]))
    );

    assert_eq!(exts[3].id, IntOrOid::Int(3));
    assert!(!exts[3].critical);
    match &exts[3].value {
        ExtensionValue::SubjectAltName(names) => match names.as_slice() {
            [
                c509_cert::GeneralName {
                    kind: 2,
                    value: c509_cert::GeneralNameValue::DnsName(s),
                },
            ] => assert_eq!(s, "example.com"),
            other => panic!("unexpected SAN: {other:?}"),
        },
        other => panic!("unexpected extension value: {other:?}"),
    }

    // Round trip.
    assert_eq!(cert.encode(), bytes);
}

/// Appendix A.5's `IPAddrBlocks` / `IPAddrBlocksV2` example: IPv4 prefixes
/// 192.0.2.0/24, 198.51.100.0/28, 203.0.113.0/24 and IPv6 prefix
/// 2001:db8:1234::/48 plus one IPv6 range, expressed once in the delta-coded
/// `IntIPAddressChoice` form (extension 32) and once, for the same
/// addresses via the raw-bytes `IPAddressChoice` form (extension 34).
#[test]
fn appendix_a5_ip_addr_blocks_example() {
    let bytes = build_cert_with_extensions(|e| {
        e.array(6).unwrap();
        e.i32(2).unwrap(); // keyUsage, non-critical
        e.i32(1).unwrap(); // digitalSignature

        e.i32(32).unwrap(); // id-pe-ipAddrBlocks, non-critical
        e.array(6).unwrap();
        e.u16(1).unwrap(); // AFI = IPv4
        e.null().unwrap(); // SAFI
        e.array(3).unwrap();
        e.i64(29_360_130).unwrap();
        e.i64(24_770_733_054).unwrap();
        e.i64(-24_770_012_047).unwrap();
        e.u16(2).unwrap(); // AFI = IPv6
        e.null().unwrap();
        e.array(2).unwrap();
        e.i64(316_663_873_933_876).unwrap();
        e.array(2).unwrap();
        e.i64(-316_663_852_962_606).unwrap();
        e.i64(9).unwrap();

        e.i32(34).unwrap(); // id-pe-ipAddrBlocks-v2, non-critical
        e.array(6).unwrap();
        e.u16(1).unwrap();
        e.u16(1).unwrap(); // SAFI = unicast
        e.array(3).unwrap();
        e.i64(29_360_130).unwrap();
        e.i64(24_770_733_054).unwrap();
        e.i64(-24_770_012_047).unwrap();
        e.u16(2).unwrap();
        e.u16(1).unwrap();
        e.array(2).unwrap();
        e.bytes(&hex("0020010DB81234")).unwrap();
        e.array(2).unwrap();
        e.bytes(&hex("003FFF0003")).unwrap();
        e.bytes(&hex("003FFF01220000223333445566")).unwrap();
    });

    let cert = C509Certificate::decode(&bytes).expect("decode");
    let exts = &cert.tbs.extensions.0;
    assert_eq!(exts.len(), 3);
    assert_eq!(exts[0].value, ExtensionValue::KeyUsage(1));

    let net = |s: &str| IpAddressOrRange::Prefix(s.parse::<IpNet>().unwrap());
    let range = |min: &str, max: &str| IpAddressOrRange::Range {
        min: min.parse::<IpAddr>().unwrap(),
        max: max.parse::<IpAddr>().unwrap(),
    };

    let ExtensionValue::IpAddrBlocks(families) = &exts[1].value else {
        panic!("expected IpAddrBlocks, got {:?}", exts[1].value);
    };
    assert_eq!(families.len(), 2);
    assert_eq!(families[0].afi, 1);
    assert_eq!(families[0].safi, None);
    let IpAddressChoice::Prefixes(v4) = &families[0].choice else {
        panic!("expected Prefixes");
    };
    assert_eq!(
        v4,
        &[
            net("192.0.2.0/24"),
            net("198.51.100.0/28"),
            net("203.0.113.0/24")
        ]
    );
    if let IpAddressOrRange::Prefix(p) = &v4[0] {
        assert_eq!(p.prefix_len(), 24);
    }
    if let IpAddressOrRange::Prefix(p) = &v4[1] {
        assert_eq!(p.prefix_len(), 28);
    }

    assert_eq!(families[1].afi, 2);
    let IpAddressChoice::Prefixes(v6) = &families[1].choice else {
        panic!("expected Prefixes");
    };
    assert_eq!(
        v6,
        &[
            net("2001:db8:1234::/48"),
            range("3fff:600::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"),
        ]
    );

    let ExtensionValue::IpAddrBlocksV2(families_v2) = &exts[2].value else {
        panic!("expected IpAddrBlocksV2, got {:?}", exts[2].value);
    };
    assert_eq!(families_v2[0].safi, Some(1));
    let IpAddressChoice::Prefixes(v4_v2) = &families_v2[0].choice else {
        panic!("expected Prefixes");
    };
    // Same three IPv4 prefixes, this time reached via the raw delta-int
    // form again (both extensions used IntIPAddressChoice on the wire).
    assert_eq!(v4_v2, v4);

    let IpAddressChoice::Prefixes(v6_v2) = &families_v2[1].choice else {
        panic!("expected Prefixes");
    };
    assert_eq!(
        v6_v2,
        &[
            net("2001:db8:1234::/48"),
            range("3fff:3::", "3fff:122:0:2233:3344:5566:ffff:ffff"),
        ]
    );

    // Round trip through this crate's own encoder. Not asserted byte-for-byte
    // against the original `bytes`: extension 34 was written above using the
    // raw-bytes `IPAddressChoice` wire form, but every entry here also fits
    // the more compact delta-coded `IntIPAddressChoice` form, which is what
    // `encode_ip_address_families` always prefers when possible (Section 3.3
    // "IPAddrBlocks" describes both forms as valid for these values).
    let reencoded = cert.encode();
    let reparsed = C509Certificate::decode(&reencoded).expect("re-decode");
    assert_eq!(reparsed, cert);
}

/// `serde_json::to_string` must work directly on a `C509Certificate`,
/// producing a human-readable mirror of its fields: hex strings for raw byte
/// blobs and big integers, RFC 3339 strings for timestamps, and the
/// `Display` form for exotic types like MAC addresses.
#[test]
fn serde_json_serializes_c509_certificate() {
    let bytes = hex(A1_1_DER_REENCODED);
    let cert = C509Certificate::decode_sequence(&bytes).expect("decode_sequence");

    let json = serde_json::to_string(&cert).expect("serde_json::to_string(&cert)");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    assert_eq!(
        value["tbs"]["certificate_serial_number"],
        hex::encode(cert.tbs.certificate_serial_number.to_bytes_be())
    );
    assert_eq!(
        value["tbs"]["validity_not_before"],
        cert.tbs
            .validity_not_before
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    assert_eq!(
        value["tbs"]["validity_not_after"],
        cert.tbs
            .validity_not_after
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    );
    assert_eq!(
        value["tbs"]["subject_public_key"],
        hex::encode(&cert.tbs.subject_public_key)
    );
    assert_eq!(
        value["issuer_signature_value"],
        hex::encode(&cert.issuer_signature_value)
    );

    // The compact single-commonName subject is a MAC address here (Appendix
    // A.1's worked example); confirm it comes through as its Display string,
    // not as a raw byte array.
    let RdnAttribute::Registered {
        value: SpecialText::Mac(mac),
        ..
    } = &cert.tbs.subject.0[0]
    else {
        panic!("expected a compact commonName MAC address subject");
    };
    assert_eq!(
        value["tbs"]["subject"][0]["Registered"]["value"]["Mac"],
        mac.to_string()
    );
}

/// A `C509Certificate` value must survive `serde_json::to_string` followed
/// by `serde_json::from_str` unchanged. Built directly (not decoded from
/// CBOR) so it can exercise field shapes the other worked-example vectors
/// don't: OID-form `AlgorithmIdentifier`s, an OID-identified extension, and
/// an `IpAddrBlocks` extension mixing a prefix and a range.
#[test]
fn serde_json_roundtrips_c509_certificate() {
    let cert = C509Certificate {
        tbs: TbsCertificate {
            c509_certificate_type: 3,
            certificate_serial_number: BigUint::from(128_269u32),
            issuer_signature_algorithm: AlgorithmIdentifier::Oid {
                algorithm: oid::ObjectIdentifier::try_from("1.2.840.10045.4.3.2").unwrap(),
                parameters: Some(vec![0xDE, 0xAD]),
            },
            issuer: None,
            validity_not_before: OffsetDateTime::from_unix_timestamp(1_672_531_200).unwrap(),
            validity_not_after: Some(OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap()),
            subject: Name(vec![RdnAttribute::Registered {
                id: 1,
                printable_string: false,
                value: SpecialText::Mac(MacAddr::from([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB])),
            }]),
            subject_public_key_algorithm: AlgorithmIdentifier::Oid {
                algorithm: oid::ObjectIdentifier::try_from("1.2.840.10045.2.1").unwrap(),
                parameters: None,
            },
            subject_public_key: vec![0xFE; 33],
            extensions: Extensions(vec![
                Extension {
                    id: IntOrOid::Int(2),
                    critical: false,
                    value: ExtensionValue::KeyUsage(1),
                },
                Extension {
                    id: IntOrOid::Oid(oid::ObjectIdentifier::try_from("1.2.3.4.5").unwrap()),
                    critical: true,
                    value: ExtensionValue::Raw(vec![0xAA, 0xBB]),
                },
                Extension {
                    id: IntOrOid::Int(32),
                    critical: false,
                    value: ExtensionValue::IpAddrBlocks(vec![IpAddressFamily {
                        afi: 1,
                        safi: None,
                        choice: IpAddressChoice::Prefixes(vec![
                            IpAddressOrRange::Prefix("10.0.0.0/8".parse().unwrap()),
                            IpAddressOrRange::Range {
                                min: "192.168.1.0".parse().unwrap(),
                                max: "192.168.1.255".parse().unwrap(),
                            },
                        ]),
                    }]),
                },
            ]),
        },
        issuer_signature_value: vec![0xD4, 0x32, 0x0B, 0x1D],
    };

    let json = serde_json::to_string(&cert).expect("serde_json::to_string(&cert)");
    let roundtripped: C509Certificate =
        serde_json::from_str(&json).expect("serde_json::from_str(&json)");
    assert_eq!(roundtripped, cert);
}
