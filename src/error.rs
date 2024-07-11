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
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
