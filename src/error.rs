use std::{io, string::FromUtf8Error};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("transparent")]
    Io {
        #[from]
        source: io::Error,
    },
    #[error("transparent")]
    String {
        #[from]
        source: FromUtf8Error,
    },

    #[error("transparent")]
    Argon2 {
        #[from]
        source: argon2::Error,
    },

    #[error("transparent")]
    Ed25519SignatureError {
        #[from]
        source: ed25519_dalek_bip32::Error,
    },
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
