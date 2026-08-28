use core::fmt;

/// Errors that can occur while decoding a C509 certificate.
#[derive(Debug)]
pub enum Error {
    /// A low-level CBOR decoding error (malformed CBOR, truncated input,
    /// unexpected major type, ...).
    Cbor(minicbor::decode::Error),
    /// The CBOR was well-formed but did not match the C509 grammar.
    Malformed(&'static str),
    /// [`crate::from_x509`] could not convert the input X.509 certificate
    /// (unparseable DER/PEM, or an OID/extension form this converter
    /// doesn't recognize).
    X509(String),
    /// [`crate::from_json`] could not build a certificate from the input
    /// JSON (malformed JSON, or a value that doesn't satisfy the schema).
    Json(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "CBOR decode error: {e}"),
            Error::Malformed(msg) => write!(f, "malformed C509 certificate: {msg}"),
            Error::X509(msg) => write!(f, "X.509 conversion error: {msg}"),
            Error::Json(msg) => write!(f, "JSON conversion error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Cbor(e) => Some(e),
            Error::Malformed(_) | Error::X509(_) | Error::Json(_) => None,
        }
    }
}

impl From<minicbor::decode::Error> for Error {
    fn from(e: minicbor::decode::Error) -> Self {
        Error::Cbor(e)
    }
}

impl Error {
    pub(crate) fn malformed(msg: &'static str) -> Self {
        Error::Malformed(msg)
    }

    pub(crate) fn into_minicbor(self) -> minicbor::decode::Error {
        match self {
            Error::Cbor(e) => e,
            Error::Malformed(m) => minicbor::decode::Error::message(m),
            Error::X509(_) => unreachable!("X509 errors are never produced while decoding CBOR"),
            Error::Json(_) => unreachable!("Json errors are never produced while decoding CBOR"),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
