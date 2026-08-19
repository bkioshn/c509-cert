# c509-cert

[![crates.io](https://img.shields.io/crates/v/c509-cert.svg)](https://crates.io/crates/c509-cert)
[![docs.rs](https://img.shields.io/docsrs/c509-cert)](https://docs.rs/c509-cert)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A Rust parser and encoder for **C509 Certificates** — the CBOR encoding of
X.509 certificates specified by
[`draft-ietf-cose-cbor-encoded-cert-19`](https://datatracker.ietf.org/doc/draft-ietf-cose-cbor-encoded-cert/).

```text
C509Certificate = [
   TBSCertificate,
   issuerSignatureValue : any,
]
```

C509 re-encodes X.509 into CBOR to shrink certificates for constrained
environments (e.g. IoT, COSE/CWT-based protocols) without changing the
semantics X.509 already defines.

## Scope

This crate parses and builds the **C509 CBOR wire structures**. It does
**not** verify signatures or validate certificate semantics (path building,
name constraints enforcement, time validity, ...) — it's a codec, not a
certificate validator.

`from_x509` converts a real X.509 certificate into a `C509Certificate`
(`c509CertificateType = 3`, "DER re-encoded"), but only at the structural
level: it does not repack public keys or signature values (no EC point
compression, no RSA exponent elision, no ECDSA `R‖S` packing) — those are
carried as opaque bytes exactly as they appear on the wire, and only a
handful of common algorithms/extensions are recognized. See its docs for
exactly what's supported.

## Features

- Decode/encode `C509Certificate` in both wire forms: the CBOR
  array-wrapped form and the bare CBOR Sequence form.
- `TBSCertificate` fields: serial number, issuer/subject `Name` (RDN
  attributes), validity, subject public key, signature algorithms.
- Extensions, including `BasicConstraints`, `KeyUsage`, `ExtKeyUsage`,
  `SubjectAltName`/`IssuerAltName` (`GeneralName`), `AuthorityKeyIdentifier`,
  `CRLDistributionPoints`, `CertificatePolicies`, `AuthorityInfoAccess`,
  `SubjectDirectoryAttributes`, `NameConstraints`, `PolicyMappings`,
  `PolicyConstraints`, and IP address/AS ID extensions (RFC 3779).
- `from_x509`: convert a real X.509 certificate (PEM or DER) straight into
  a `C509Certificate`.
- A CLI (`c509-cert`) for decoding hex-encoded C509 certificates, building
  one from a JSON description, and converting a real X.509 certificate
  (PEM/DER) straight into C509 hex.

## Library usage

```rust
use c509_cert::C509Certificate;

// A CBOR Sequence-encoded C509 certificate (no outer array header).
let bytes: &[u8] = /* ... */
# &[];

let cert = C509Certificate::decode_sequence(bytes)?;
println!("{:#?}", cert.tbs.subject);

// Round-trip back to bytes.
let reencoded = cert.encode_sequence();
# Ok::<(), c509_cert::Error>(())
```

Converting a real X.509 certificate (PEM or DER, auto-detected):

```rust
let pem_bytes: &[u8] = /* ... */
# &[];

let cert = c509_cert::from_x509(pem_bytes)?;
let hex = hex::encode(cert.encode());
# Ok::<(), c509_cert::Error>(())
```

Add it to `Cargo.toml`:

```toml
[dependencies]
c509-cert = "0.1"
```

See [docs.rs](https://docs.rs/c509-cert) for the full API.

## CLI usage

```text
Usage: c509-cert [HEX]
       c509-cert --from-json <FILE> [--sequence]
       c509-cert --from-x509 <FILE> [--sequence]

Decode a hex-encoded C509 certificate and print its structure, build one
from a JSON description and print its hex encoding, or convert a real
X.509 certificate (PEM or DER) straight into C509 hex.

Decoding always auto-detects which of the two wire forms HEX is in
(array-wrapped vs bare CBOR Sequence); --sequence has no effect there.

Arguments:
  HEX          Hex-encoded certificate bytes. If omitted, read from stdin.

Options:
      --sequence    Emit the bare CBOR Sequence form instead of the default
                    CBOR array-wrapped form. Applies to --from-json and
                    --from-x509 output; has no effect when decoding HEX.
      --from-json <FILE>
                    Build a C509Certificate from a JSON file instead of
                    decoding HEX, and print its hex encoding.
      --from-x509 <FILE>
                    Convert a PEM- or DER-encoded X.509 certificate straight
                    into C509 hex.
  -h, --help        Print this help message and exit.
```

### Examples

Build a certificate from JSON (see [`examples/c509.json`](examples/c509.json)
for the schema) and print its hex encoding:

```sh
cargo run -- --from-json examples/c509.json
```

Decode that hex back into a structure:

```sh
cargo run -- --from-json examples/c509.json | xargs cargo run --
```

Convert a real X.509 certificate into C509:

```sh
cargo run -- --from-x509 examples/x509.pem
```

`--from-x509` targets `c509CertificateType = 3` ("DER re-encoded"): the
public key and signature are carried through as opaque bytes with no
algorithm-specific repacking, and only a handful of common
algorithms/extensions are recognized. It's meant for exercising the CLI
against real-world certificates, not as a byte-accurate implementation of
the draft's DER↔C509 conversion rules.

## Development

```sh
cargo build
cargo test
cargo clippy --all-targets
```

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
