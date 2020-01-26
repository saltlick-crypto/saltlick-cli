// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::io;
use std::path::PathBuf;

use saltlick::SaltlickKeyIoError;

#[derive(Debug)]
pub enum CliError {
    BothKeyAndPath {
        type_: String,
    },
    InputFileIoError {
        error: io::Error,
        path: PathBuf,
    },
    KeychainError {
        error: KeychainError,
    },
    KeyExists {
        path: PathBuf,
        type_: String,
    },
    KeyLoadError {
        error: SaltlickKeyIoError,
        path: PathBuf,
        type_: String,
    },
    MissingKeyAndPath {
        type_: String,
    },
    OutputFileIoError {
        error: io::Error,
        path: PathBuf,
    },
    SaltlickKeyIoError {
        error: SaltlickKeyIoError,
    },
    StreamIoError {
        error: io::Error,
    },
}

impl StdError for CliError {}

impl Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::CliError::*;
        match self {
            BothKeyAndPath { type_ } => write!(
                f,
                "only one of \"--key\" or \"--{}\" can be specified",
                type_
            ),
            InputFileIoError { error, path } => write!(
                f,
                "unable to read input file \"{}\": {}",
                path.to_string_lossy(),
                error
            ),
            KeychainError { error } => Display::fmt(error, f),
            KeyExists { path, type_ } => write!(
                f,
                "{} key already exists at \"{}\"",
                type_,
                path.to_string_lossy(),
            ),
            KeyLoadError { error, path, type_ } => write!(
                f,
                "unable to load {} key from \"{}\": {}",
                type_,
                path.to_string_lossy(),
                error,
            ),
            MissingKeyAndPath { type_ } => {
                write!(f, "one of \"--key\" or \"--{}\" must be specified", type_)
            }
            OutputFileIoError { error, path } => write!(
                f,
                "unable to write output file \"{}\": {}",
                path.to_string_lossy(),
                error
            ),
            SaltlickKeyIoError { error } => Display::fmt(error, f),
            StreamIoError { error } => {
                write!(f, "error occurred while performing file I/O: {}", error)
            }
        }
    }
}

impl From<KeychainError> for CliError {
    fn from(error: KeychainError) -> CliError {
        CliError::KeychainError { error }
    }
}

impl From<SaltlickKeyIoError> for CliError {
    fn from(error: SaltlickKeyIoError) -> CliError {
        CliError::SaltlickKeyIoError { error }
    }
}

#[derive(Debug)]
pub enum KeychainError {
    BadKeychainDir {
        error: io::Error,
        path: PathBuf,
    },
    DeleteError {
        name: String,
        error: io::Error,
    },
    InvalidKeypairName {
        name: String,
        error: InvalidKeypairName,
    },
    KeychainOpenError {
        path: PathBuf,
        error: io::Error,
    },
    KeypairAlreadyExists {
        name: String,
    },
    KeypairNotFound {
        name: String,
    },
    LoadError {
        name: String,
        error: SaltlickKeyIoError,
    },
    PublicKeyNotFound,
    SaveError {
        name: String,
        error: SaltlickKeyIoError,
    },
}

impl StdError for KeychainError {}

impl Display for KeychainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::KeychainError::*;
        match self {
            BadKeychainDir { error, path } => write!(
                f,
                "keychain path \"{}\" is invalid: {}",
                path.to_string_lossy(),
                error
            ),
            DeleteError { name, error } => write!(f, "error deleting key \"{}\": {}", name, error),
            InvalidKeypairName { name, error } => {
                write!(f, "keypair name \"{}\" is invalid: {}", name, error)
            }
            KeychainOpenError { path, error } => write!(
                f,
                "unable to access saltlick config directory \"{}\": {}",
                path.to_string_lossy(),
                error
            ),
            KeypairAlreadyExists { name } => write!(f, "keypair \"{}\" already exists", name),
            KeypairNotFound { name } => write!(f, "keypair \"{}\" not found", name),
            LoadError { name, error } => write!(f, "error loading key \"{}\": {}", name, error),
            PublicKeyNotFound => write!(f, "no matching keypair found for public key"),
            SaveError { name, error } => write!(f, "error saving key \"{}\": {}", name, error),
        }
    }
}

#[derive(Debug)]
pub enum InvalidKeypairName {
    BadChar(char),
    Empty,
}

impl StdError for InvalidKeypairName {}

impl Display for InvalidKeypairName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::InvalidKeypairName::*;
        match self {
            BadChar(c) => write!(f, "invalid character \"{}\"", c),
            Empty => write!(f, "name cannot be empty"),
        }
    }
}
