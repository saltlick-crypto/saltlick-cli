// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Simple CLI for encrypting and decrypting saltlick file streams.

mod cli;
mod error;
mod keychain;

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use human_panic::setup_panic;
use saltlick::{
    self,
    bufread::{SaltlickDecrypter, SaltlickEncrypter},
    PublicKey, SecretKey,
};

use crate::cli::*;
use crate::error::CliError;
use crate::keychain::Keychain;

/// Opens and returns `path` for `Read` if it is `Some`, otherwise returns
/// stdin.
fn read_or_stdin(path: Option<impl AsRef<Path>>) -> Result<Box<dyn BufRead>, CliError> {
    if let Some(input_file) = path.as_ref() {
        Ok(Box::new(
            File::open(input_file)
                .map(BufReader::new)
                .map_err(|error| CliError::InputFileIoError {
                    error,
                    path: input_file.as_ref().to_path_buf(),
                })?,
        ))
    } else {
        Ok(Box::new(BufReader::new(io::stdin())))
    }
}

/// Opens and returns `path` for `Write` if it is `Some`, otherwise returns
/// stdout. If `force` is false, opening an existing file is an error,
/// otherwise the file is truncated and no error is raised.
fn write_or_stdout(
    path: Option<impl AsRef<Path>>,
    force: bool,
) -> Result<Box<dyn Write>, CliError> {
    if let Some(output_file) = path.as_ref() {
        let writer = if force {
            File::create(output_file).map_err(|error| CliError::OutputFileIoError {
                error,
                path: output_file.as_ref().to_path_buf(),
            })?
        } else {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(output_file)
                .map_err(|error| CliError::OutputFileIoError {
                    error,
                    path: output_file.as_ref().to_path_buf(),
                })?
        };
        Ok(Box::new(writer))
    } else {
        Ok(Box::new(io::stdout()))
    }
}

/// Checks options on commands that take either a public key path
/// (i.e.  -p/--public) or a keychain name (-k/--key), returning the
/// appropriate `PublicKey` or error.
fn get_public_key(
    path: Option<impl AsRef<Path>>,
    name: Option<impl AsRef<str>>,
) -> Result<PublicKey, CliError> {
    let public_string = String::from("public");
    match (path.as_ref(), name.as_ref()) {
        (Some(_), Some(_)) => Err(CliError::BothKeyAndPath {
            type_: public_string,
        }),
        (Some(path), None) => {
            Ok(
                PublicKey::from_file(path).map_err(|error| CliError::KeyLoadError {
                    error,
                    path: path.as_ref().to_path_buf(),
                    type_: public_string,
                })?,
            )
        }
        (None, Some(name)) => Ok(Keychain::open()?.get(name)?.public().clone()),
        (None, None) => Err(CliError::MissingKeyAndPath {
            type_: public_string,
        }),
    }
}

/// Checks options on commands that take either a secret key path
/// (i.e.  -p/--secret) or a keychain name (-k/--key), returning the
/// appropriate `SecretKey` or error.
fn get_secret_key(
    path: Option<impl AsRef<Path>>,
    name: Option<impl AsRef<str>>,
) -> Result<SecretKey, CliError> {
    let secret_string = String::from("secret");
    match (path.as_ref(), name.as_ref()) {
        (Some(_), Some(_)) => Err(CliError::BothKeyAndPath {
            type_: secret_string,
        }),
        (Some(path), None) => {
            Ok(
                SecretKey::from_file(path).map_err(|error| CliError::KeyLoadError {
                    error,
                    path: path.as_ref().to_path_buf(),
                    type_: secret_string,
                })?,
            )
        }
        (None, Some(name)) => Ok(Keychain::open()?.get(name)?.secret().clone()),
        (None, None) => Err(CliError::MissingKeyAndPath {
            type_: secret_string,
        }),
    }
}

/// Decrypts input - either from stdin or an input file - and writes it to
/// stdout or an output file. If no information about which key to use is
/// provided, automatically looks for a matching key in the keychain.
fn decrypt(args: DecryptArgs) -> Result<(), CliError> {
    let infile = read_or_stdin(args.infile.as_ref())?;
    let mut outfile = write_or_stdout(args.outfile.as_ref(), args.force)?;
    let mut decrypter = if args.public.is_none() && args.key.is_none() {
        let keychain = Keychain::open()?;
        let lookup = move |key: &PublicKey| -> Option<SecretKey> {
            keychain
                .find(key)
                .map(|keypair| keypair.secret().clone())
                .ok()
        };
        SaltlickDecrypter::new_deferred(infile, lookup)
    } else {
        let public = get_public_key(args.public.as_ref(), args.key.as_ref())?;
        let secret = get_secret_key(args.secret.as_ref(), args.key.as_ref())?;
        SaltlickDecrypter::new(public, secret, infile)
    };
    io::copy(&mut decrypter, &mut outfile).map_err(|error| CliError::StreamIoError { error })?;
    Ok(())
}

/// Encrypts input - either from stdin or an input file - and writes it to
/// stdout or an output file. Request that the key is specified - there's no
/// reasonable default for encryption, unlike decryption.
fn encrypt(args: EncryptArgs) -> Result<(), CliError> {
    let public = get_public_key(args.public.as_ref(), args.key.as_ref())?;
    let infile = read_or_stdin(args.infile.as_ref())?;
    let mut outfile = write_or_stdout(args.outfile.as_ref(), args.force)?;
    let mut encrypter = SaltlickEncrypter::new(public, infile);
    io::copy(&mut encrypter, &mut outfile).map_err(|error| CliError::StreamIoError { error })?;
    Ok(())
}

/// Generates a brand new key pair and writes it to the paths provided.
fn generate(args: GenerateArgs) -> Result<(), CliError> {
    let (public, secret) = saltlick::gen_keypair();
    let public_path = args.public.unwrap_or_else(|| PathBuf::from("public.pem"));
    let secret_path = args.secret.unwrap_or_else(|| PathBuf::from("secret.pem"));
    if public_path.is_file() {
        return Err(CliError::KeyExists {
            path: public_path,
            type_: String::from("public"),
        });
    }
    if secret_path.is_file() {
        return Err(CliError::KeyExists {
            path: secret_path,
            type_: String::from("secret"),
        });
    }
    public.to_file(&public_path)?;
    println!("Wrote public key \"{}\"", public_path.to_string_lossy());
    secret.to_file(&secret_path)?;
    println!("Wrote secret key \"{}\"", secret_path.to_string_lossy());
    Ok(())
}

/// Operations on the saltlick CLI keychain, a convenience for saving keys to
/// avoid needing to always specify full paths to key locations.
fn keychain(args: KeychainArgs) -> Result<(), CliError> {
    use self::KeychainArgs::*;
    let keychain = Keychain::open()?;
    match args {
        Export {
            name,
            public,
            secret,
        } => {
            let keypair = keychain.get(name)?;
            if let Some(path) = public {
                keypair.public().to_file(&path)?;
                println!("Exported public key \"{}\"", path.to_string_lossy());
            }
            if let Some(path) = secret {
                keypair.secret().to_file(&path)?;
                println!("Exported secret key \"{}\"", path.to_string_lossy());
            }
            Ok(())
        }
        Generate { name } => {
            let (public, secret) = saltlick::gen_keypair();
            keychain.create(&name, public, secret)?;
            println!("Created keypair \"{}\"", name);
            Ok(())
        }
        Import {
            name,
            public,
            secret,
        } => {
            let public = get_public_key(Some(public), None as Option<&str>)?;
            let secret = get_secret_key(Some(secret), None as Option<&str>)?;
            keychain.create(&name, public, secret)?;
            println!("Imported keypair \"{}\"", name);
            Ok(())
        }
        List => {
            for keypair in keychain.iter()? {
                println!("{}", keypair.name());
            }
            Ok(())
        }
        Remove { name } => {
            keychain.remove(&name)?;
            println!("Removed keypair \"{}\"", name);
            Ok(())
        }
        Rename { old_name, new_name } => {
            keychain.rename(&old_name, &new_name)?;
            println!("Renamed \"{}\" -> \"{}\"", old_name, new_name);
            Ok(())
        }
    }
}

fn main() {
    setup_panic!();

    let result = match Cli::from_args().cmd {
        Command::Decrypt(args) => decrypt(args),
        Command::Encrypt(args) => encrypt(args),
        Command::Generate(args) => generate(args),
        Command::Keychain(args) => keychain(args),
    };

    match result {
        Ok(()) => ::std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {}", e);
            ::std::process::exit(1);
        }
    }
}
