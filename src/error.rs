use core::fmt;

/// Errors that can occur while decoding a C509 certificate.
#[derive(Debug)]
pub enum Error {
    /// A low-level CBOR decoding error (malformed CBOR, truncated input,
    /// unexpected major type, ...).
    Cbor(minicbor::decode::Error),
    /// The CBOR was well-formed but did not match the C509 grammar.
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "CBOR decode error: {e}"),
            Error::Malformed(msg) => write!(f, "malformed C509 certificate: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Cbor(e) => Some(e),
            Error::Malformed(_) => None,
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
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
