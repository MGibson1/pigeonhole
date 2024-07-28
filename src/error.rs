use std::{error, io, string::FromUtf8Error};

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

    #[error("transparent")]
    DigestInvalidLength(#[from] sha2::digest::InvalidLength),

    #[error("transparent")]
    HkdfInvalidLength(#[from] hkdf::InvalidLength),

    #[error("transparent")]
    AesGcm(#[from] aes_gcm::Error),

    #[error("transparent")]
    SymmetricCryptoKeyError(#[from] SymmetricKeyError),

    #[error("transparent")]
    Uuid(#[from] uuid::Error),

    #[error("failed to parse chunk id from file stream")]
    ParseChunkIdError,
}

#[derive(Error, Debug)]
pub enum SymmetricKeyError {
    #[error("Cannot derive chunk key for a previous chunk")]
    InvalidChunkDeriveError,
    #[error("Invalid chunk id")]
    InvalidChunkId,
    #[error("Invalid file id")]
    InvalidFileId,
    #[error("Invalid encryption type {0}")]
    InvalidEncryptionType(u8),
    #[error("Wrong encryption type")]
    WrongEncryptionType,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
