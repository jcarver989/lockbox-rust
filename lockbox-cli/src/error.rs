use argon2::password_hash;
use prost;
use std::fmt;
use xsalsa20poly1305::aead;

#[derive(Debug)]
pub enum Error {
    HashError(password_hash::Error),
    AeadError(aead::Error),
    IOError(std::io::Error),
    DecodeError(prost::DecodeError),
}

impl Error {
    pub fn new_invalid_data_error(msg: &str) -> Error {
        Error::IOError(std::io::Error::new(std::io::ErrorKind::InvalidData, msg))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HashError(e) => write!(f, "{}", e),
            Error::AeadError(e) => write!(f, "{}", e),
            Error::IOError(e) => write!(f, "{}", e),
            Error::DecodeError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self)
    }
}

impl From<prost::DecodeError> for Error {
    fn from(e: prost::DecodeError) -> Self {
        Error::DecodeError(e)
    }
}

impl From<password_hash::Error> for Error {
    fn from(e: password_hash::Error) -> Self {
        Error::HashError(e)
    }
}

impl From<aead::Error> for Error {
    fn from(e: aead::Error) -> Self {
        Error::AeadError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}
