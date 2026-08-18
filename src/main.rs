use std::io::Read;

use c509_cert::C509Certificate;
use minicbor::Decoder;
use minicbor::data::Type;

mod cert_json;
mod x509_to_c509;

fn hex_decode(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(s)
}

/// Decode either wire form, auto-detected from the first byte: the
/// array-wrapped form always starts with a CBOR array header, the bare
/// CBOR-sequence form never does (it starts with `c509CertificateType`, an
/// int) — so there's nothing for a caller to disambiguate.
fn decode_certificate(bytes: &[u8]) -> c509_cert::Result<C509Certificate> {
    match Decoder::new(bytes).datatype() {
        Ok(Type::Array | Type::ArrayIndef) => C509Certificate::decode(bytes),
        _ => C509Certificate::decode_sequence(bytes),
    }
}

fn print_usage() {
    println!(
        "Usage: c509-cert [HEX]
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
                    decoding HEX, and print its hex encoding. See the crate
                    docs for `cert_json::JsonCertificate` for the schema.
      --from-x509 <FILE>
                    Convert a PEM- or DER-encoded X.509 certificate straight
                    into C509 hex. Uses c509CertificateType = 3 (\"DER
                    re-encoded\") semantics: the public key and signature
                    are carried through as opaque bytes with no
                    algorithm-specific repacking, and only a handful of
                    common algorithms/extensions are recognized. See
                    `x509_to_c509.rs` for exactly what's supported.
  -h, --help        Print this help message and exit."
    );
}

fn encode_from_json(path: &str, sequence: bool) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });
    let json: cert_json::JsonCertificate = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("failed to parse {path}: {e}");
        std::process::exit(1);
    });
    let cert = json.into_certificate().unwrap_or_else(|e| {
        eprintln!("failed to build certificate: {e}");
        std::process::exit(1);
    });
    let bytes = if sequence {
        cert.encode_sequence()
    } else {
        cert.encode()
    };
    println!("{}", hex::encode(bytes));
}

fn convert_from_x509(path: &str, sequence: bool) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("failed to read {path}: {e}");
        std::process::exit(1);
    });
    let bytes = x509_to_c509::convert_to_bytes(&bytes, sequence).unwrap_or_else(|e| {
        eprintln!("failed to convert {path}: {e}");
        std::process::exit(1);
    });
    println!("{}", hex::encode(bytes));
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }

    let sequence = if let Some(pos) = args.iter().position(|a| a == "--sequence") {
        args.remove(pos);
        true
    } else {
        false
    };

    if let Some(pos) = args.iter().position(|a| a == "--from-json") {
        args.remove(pos);
        if args.is_empty() {
            eprintln!("--from-json requires a file path");
            std::process::exit(1);
        }
        encode_from_json(&args.remove(0), sequence);
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--from-x509") {
        args.remove(pos);
        if args.is_empty() {
            eprintln!("--from-x509 requires a file path");
            std::process::exit(1);
        }
        convert_from_x509(&args.remove(0), sequence);
        return;
    }

    let hex = if let Some(arg) = args.into_iter().next() {
        arg
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .expect("failed to read hex from stdin");
        buf
    };

    let bytes = hex_decode(hex.trim()).unwrap_or_else(|e| {
        eprintln!("invalid hex input: {e}");
        std::process::exit(1);
    });

    match decode_certificate(&bytes) {
        Ok(cert) => println!("{cert:#?}"),
        Err(e) => {
            eprintln!("failed to decode C509Certificate: {e}");
            std::process::exit(1);
        }
    }
}
