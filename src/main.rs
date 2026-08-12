use std::io::Read;

use c509_cert::C509Certificate;

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have an even number of digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let sequence = if let Some(pos) = args.iter().position(|a| a == "--sequence") {
        args.remove(pos);
        true
    } else {
        false
    };

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

    let result = if sequence {
        C509Certificate::decode_sequence(&bytes)
    } else {
        C509Certificate::decode(&bytes)
    };

    match result {
        Ok(cert) => println!("{cert:#?}"),
        Err(e) => {
            eprintln!("failed to decode C509Certificate: {e}");
            std::process::exit(1);
        }
    }
}
