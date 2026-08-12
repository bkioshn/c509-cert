//! Human-readable name lookups for the IANA "CBOR Encoded X.509 (C509)"
//! registry tables defined in `draft-ietf-cose-cbor-encoded-cert-19` Section
//! 8. Transcribed verbatim from the draft text.
//!
//! These are deliberately *not* closed enums: every table reserves ranges
//! for future IANA assignment and/or Private Use (generally `>= 32768`), so
//! a conforming parser must accept and preserve unrecognized-but-valid
//! integer values rather than reject them. All identifier fields on the
//! public structs are therefore plain integers; these functions are a
//! best-effort `Display`/debugging aid layered on top.

/// Section 8.6 "C509 RDN Attributes Registry" (Figure 10).
pub fn rdn_attribute_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0 => "emailAddress",
        1 => "commonName",
        2 => "surname",
        3 => "serialNumber",
        4 => "countryName",
        5 => "localityName",
        6 => "stateOrProvinceName",
        7 => "streetAddress",
        8 => "organizationName",
        9 => "organizationalUnitName",
        10 => "title",
        11 => "businessCategory",
        12 => "postalCode",
        13 => "givenName",
        14 => "initials",
        15 => "generationQualifier",
        16 => "dnQualifier",
        17 => "pseudonym",
        18 => "organizationIdentifier",
        19 => "jurisdictionLocalityName",
        20 => "jurisdictionStateOrProvinceName",
        21 => "jurisdictionCountryName",
        22 => "domainComponent",
        25 => "name",
        26 => "telephoneNumber",
        27 => "dmdName",
        28 => "uid",
        29 => "unstructuredName",
        30 => "unstructuredAddress",
        _ => return None,
    })
}

/// Section 8.8 "C509 Extensions Registry" (Figure 12).
pub fn extension_name(id: u16) -> Option<&'static str> {
    Some(match id {
        1 => "subjectKeyIdentifier",
        2 => "keyUsage",
        3 => "subjectAltName",
        4 => "basicConstraints",
        5 => "cRLDistributionPoints",
        6 => "certificatePolicies",
        7 => "authorityKeyIdentifier",
        8 => "extKeyUsage",
        9 => "authorityInfoAccess",
        24 => "subjectDirectoryAttributes",
        25 => "issuerAltName",
        26 => "nameConstraints",
        27 => "policyMappings",
        28 => "policyConstraints",
        29 => "freshestCRL",
        30 => "inhibitAnyPolicy",
        31 => "subjectInfoAccess",
        32 => "id-pe-ipAddrBlocks",
        33 => "id-pe-autonomousSysIds",
        34 => "id-pe-ipAddrBlocks-v2",
        35 => "id-pe-autonomousSysIds-v2",
        36 => "id-pkix-ocsp-nocheck",
        38 => "id-pe-tlsfeature",
        _ => return None,
    })
}

/// Section 8.12 "C509 Extended Key Usages Registry" (Figure 16).
pub fn extended_key_usage_name(id: i16) -> Option<&'static str> {
    Some(match id {
        0 => "anyExtendedKeyUsage",
        1 => "id-kp-serverAuth",
        2 => "id-kp-clientAuth",
        3 => "id-kp-codeSigning",
        4 => "id-kp-emailProtection",
        8 => "id-kp-timeStamping",
        9 => "id-kp-OCSPSigning",
        10 => "id-pkinit-KPClientAuth",
        11 => "id-pkinit-KPKdc",
        12 => "id-kp-secureShellClient",
        13 => "id-kp-secureShellServer",
        14 => "id-kp-bundleSecurity",
        15 => "id-kp-cmcCA",
        16 => "id-kp-cmcRA",
        17 => "id-kp-cmcArchive",
        18 => "id-kp-cmKGA",
        20 => "id-kp-wisun-fan-device",
        _ => return None,
    })
}

/// Section 8.13 "C509 General Names Registry" (Figure 17).
pub fn general_name_type_name(id: i32) -> Option<&'static str> {
    Some(match id {
        -3 => "otherName (MACAddress)",
        -2 => "otherName (SmtpUTF8Mailbox)",
        -1 => "otherName (hardwareModuleName)",
        0 => "otherName",
        1 => "rfc822Name",
        2 => "dNSName",
        4 => "directoryName",
        6 => "uniformResourceIdentifier",
        7 => "iPAddress",
        8 => "registeredID",
        _ => return None,
    })
}

/// Section 8.14 "C509 Signature Algorithms Registry" (Figure 18).
pub fn signature_algorithm_name(id: i32) -> Option<&'static str> {
    Some(match id {
        -256 => "sha1-with-rsa-signature",
        -255 => "ecdsa-with-SHA1",
        0 => "ecdsa-with-SHA256",
        1 => "ecdsa-with-SHA384",
        2 => "ecdsa-with-SHA512",
        3 => "id-ecdsa-with-shake128",
        4 => "id-ecdsa-with-shake256",
        5 => "id-alg-unsigned",
        8 => "sm2-with-sm3",
        12 => "id-Ed25519",
        13 => "id-Ed448",
        14 => "sa-ecdhPop-sha256-hmac-sha256",
        15 => "sa-ecdhPop-sha384-hmac-sha384",
        16 => "sa-ecdhPop-sha512-hmac-sha512",
        23 => "sha256WithRSAEncryption",
        24 => "sha384WithRSAEncryption",
        25 => "sha512WithRSAEncryption",
        26 => "RSASSA-PSS with SHA-256",
        27 => "RSASSA-PSS with SHA-384",
        28 => "RSASSA-PSS with SHA-512",
        29 => "id-RSASSA-PSS-SHAKE128",
        30 => "id-RSASSA-PSS-SHAKE256",
        _ => return None,
    })
}

/// Section 8.15 "C509 Public Key Algorithms Registry" (Figure 19).
pub fn public_key_algorithm_name(id: i32) -> Option<&'static str> {
    Some(match id {
        0 => "rsaEncryption",
        1 => "id-ecPublicKey (secp256r1)",
        2 => "id-ecPublicKey (secp384r1)",
        3 => "id-ecPublicKey (secp521r1)",
        6 => "id-ecPublicKey (sm2p256v1)",
        8 => "id-X25519",
        9 => "id-X448",
        12 => "id-Ed25519",
        13 => "id-Ed448",
        24 => "id-ecPublicKey (brainpoolP256r1)",
        25 => "id-ecPublicKey (brainpoolP384r1)",
        26 => "id-ecPublicKey (brainpoolP512r1)",
        27 => "id-ecPublicKey (FRP256v1)",
        _ => return None,
    })
}

/// Section 8.11 "C509 Information Access Registry" (Figure 15), used for the
/// `accessMethod` of `authorityInfoAccess`/`subjectInfoAccess`.
pub fn information_access_name(id: i16) -> Option<&'static str> {
    Some(match id {
        1 => "id-ad-ocsp",
        2 => "id-ad-caIssuers",
        3 => "id-ad-timeStamping",
        5 => "id-ad-caRepository",
        10 => "id-ad-rpkiManifest",
        11 => "id-ad-signedObject",
        13 => "id-ad-rpkiNotify",
        _ => return None,
    })
}
