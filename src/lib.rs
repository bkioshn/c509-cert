//! A parser/encoder for **C509 Certificates** — the CBOR encoding of X.509
//! certificates specified by
//! [`draft-ietf-cose-cbor-encoded-cert-19`](https://datatracker.ietf.org/doc/draft-ietf-cose-cbor-encoded-cert/)
//! (an active IETF Internet-Draft, not yet an RFC), built on top of
//! [`minicbor`].
//!
//! ```text
//! C509Certificate = [
//!    TBSCertificate,
//!    issuerSignatureValue : any,
//! ]
//! ```
//!
//! # Example
//!
//! ```
//! use c509_cert::C509Certificate;
//!
//! // The Appendix A.1.1 example from the draft (CBOR re-encoding of a
//! // DER-encoded RFC 7925 profiled X.509 certificate), as a CBOR Sequence
//! // (no outer array header).
//! let bytes = [
//!     0x03, 0x43, 0x01, 0xf5, 0x0d, 0x00, 0x6b, 0x52, 0x46, 0x43, 0x20, 0x74, 0x65, 0x73, 0x74,
//!     0x20, 0x43, 0x41, 0x1a, 0x63, 0xb0, 0xcd, 0x00, 0x1a, 0x69, 0x55, 0xb9, 0x00, 0xd8, 0x30,
//!     0x46, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x01, 0x58, 0x21, 0xfe, 0xb1, 0x21, 0x6a, 0xb9,
//!     0x6e, 0x5b, 0x3b, 0x33, 0x40, 0xf5, 0xbd, 0xf0, 0x2e, 0x69, 0x3f, 0x16, 0x21, 0x3a, 0x04,
//!     0x52, 0x5e, 0xd4, 0x44, 0x50, 0xb1, 0x01, 0x9c, 0x2d, 0xfd, 0x38, 0x38, 0xab, 0x01, 0x58,
//!     0x40, 0xd4, 0x32, 0x0b, 0x1d, 0x68, 0x49, 0xe3, 0x09, 0x21, 0x9d, 0x30, 0x03, 0x7e, 0x13,
//!     0x81, 0x66, 0xf2, 0x50, 0x82, 0x47, 0xdd, 0xda, 0xe7, 0x6c, 0xce, 0xea, 0x55, 0x05, 0x3c,
//!     0x10, 0x8e, 0x90, 0xd5, 0x51, 0xf6, 0xd6, 0x01, 0x06, 0xf1, 0xab, 0xb4, 0x84, 0xcf, 0xbe,
//!     0x62, 0x56, 0xc1, 0x78, 0xe4, 0xac, 0x33, 0x14, 0xea, 0x19, 0x19, 0x1e, 0x8b, 0x60, 0x7d,
//!     0xa5, 0xae, 0x3b, 0xda, 0x16,
//! ];
//!
//! let cert = C509Certificate::decode_sequence(&bytes)?;
//! assert_eq!(cert.tbs.c509_certificate_type, 3);
//! assert_eq!(cert.tbs.subject_public_key_algorithm, c509_cert::AlgorithmIdentifier::Int(1));
//! # Ok::<(), c509_cert::Error>(())
//! ```
//!
//! # Scope
//!
//! This crate parses and builds the **C509 CBOR wire structures**. It does
//! not perform X.509 DER ↔ C509 conversion (point compression, RSA
//! exponent-elision, ECDSA `R‖S` packing, ...); public keys and signature
//! values are carried as opaque bytes exactly as they appear on the wire.
//! It also does not verify signatures or validate certificate semantics
//! (path building, name constraints enforcement, time validity, ...) —
//! it is a codec, not a certificate validator.

mod algorithm;
mod certificate;
mod common;
mod error;
mod extensions;
mod name;
mod oid;
pub mod registry;

pub use algorithm::AlgorithmIdentifier;
pub use certificate::{C509Certificate, TbsCertificate};
pub use common::{IntOrOid, SpecialText};
pub use error::{Error, Result};
pub use extensions::ip_addr::{AddressPrefix, AsIdOrRange, IpAddressChoice, IpAddressFamily, IpAddressOrRange};
pub use extensions::{
    AccessDescription, AuthorityKeyIdentifier, BasicConstraints, DistributionPointName, Extension, Extensions,
    ExtensionValue, GeneralName, GeneralNameValue, NameConstraints, PolicyConstraints, PolicyInformation,
    PolicyQualifier, RdnAttributeMulti,
};
pub use name::{Name, RdnAttribute};
pub use oid::Oid;
