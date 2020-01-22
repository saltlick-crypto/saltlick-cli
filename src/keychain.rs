// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::HashSet;
use std::fmt::{self, Display};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use directories::ProjectDirs;
use saltlick::{PublicKey, SecretKey};

use crate::error::{InvalidKeypairName, KeychainError};

/// Accessor to keychain directory for saltlick CLI.
#[derive(Debug)]
pub struct Keychain {
    key_dir: PathBuf,
}

impl Keychain {
    /// Open user's keychain.
    pub fn open() -> Result<Keychain, KeychainError> {
        Self::open_at(Self::config_dir().join("keypairs"))
    }

    #[doc(hidden)]
    pub fn open_at(path: impl AsRef<Path>) -> Result<Keychain, KeychainError> {
        fs::create_dir_all(path.as_ref()).map_err(|error| KeychainError::KeychainOpenError {
            path: path.as_ref().to_path_buf(),
            error,
        })?;
        Ok(Keychain {
            key_dir: path.as_ref().to_path_buf(),
        })
    }

    fn config_dir() -> PathBuf {
        let project_dir = ProjectDirs::from("com", "bitcurry", "saltlick")
            .expect("unable to determine user home directory");
        project_dir.config_dir().to_path_buf()
    }

    /// Creates an iterator over keypairs in the keychain.
    ///
    /// Silently skips unreadable files in the keychain directory, but returns
    /// an error if the keychain directory itself is not listable.
    pub fn iter(&self) -> Result<KeychainIter, KeychainError> {
        KeychainIter::new(&self.key_dir)
    }

    /// Create a keypair with `name` and the provided `public` and `secret`
    /// keys.
    ///
    /// Attempting to create a keypair that already exists will return an
    /// error. Failing to write any of the files to disk will also return an
    /// error.
    pub fn create(
        &self,
        name: impl AsRef<str>,
        public: PublicKey,
        secret: SecretKey,
    ) -> Result<(), KeychainError> {
        let keypair_name = Keypair::parse_keypair_name(name)?;
        let keypair = Keypair {
            name: keypair_name,
            public,
            secret,
        };
        keypair.save(&self.key_dir)
    }

    /// Get the keypair with the specified `name`, if it exists.
    ///
    /// Returns an error if the keychain directory is not readable or the
    /// specified key is not found.
    pub fn get(&self, name: impl AsRef<str>) -> Result<Keypair, KeychainError> {
        Keypair::load(&self.key_dir, name)
    }

    /// Find a keypair with the matching public key, if it exists.
    ///
    /// Returns an error if the keychain directory is not readable or no
    /// matching key is found.
    pub fn find(&self, public: &PublicKey) -> Result<Keypair, KeychainError> {
        KeychainIter::new(&self.key_dir)?
            .find(|keypair| keypair.public() == public)
            .ok_or(KeychainError::PublicKeyNotFound)
    }

    /// Remove keypair with given name.
    ///
    /// Returns an error if the keychain directory is not readable or the
    /// specified key is not found.
    pub fn remove(&self, name: impl AsRef<str>) -> Result<(), KeychainError> {
        let keypair = self.get(name)?;
        keypair.delete(&self.key_dir)
    }

    /// Renames the keypair with `old_name` to `new_name`.
    ///
    /// Returns an error if the keychain directory is not readable or the
    /// specified key is not found.
    pub fn rename(
        &self,
        old_name: impl AsRef<str>,
        new_name: impl AsRef<str>,
    ) -> Result<(), KeychainError> {
        let old = self.get(old_name.as_ref())?;
        self.create(new_name, old.public().clone(), old.secret().clone())?;
        self.remove(old_name)
    }
}

/// Public/secret keypair with an associated name.
#[derive(Debug)]
pub struct Keypair {
    name: KeypairName,
    public: PublicKey,
    secret: SecretKey,
}

impl Keypair {
    /// Return the name of the keypair.
    pub fn name(&self) -> &KeypairName {
        &self.name
    }

    /// Return the public key.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Return the secret key.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    fn parse_keypair_name(name: impl AsRef<str>) -> Result<KeypairName, KeychainError> {
        KeypairName::new(name.as_ref()).map_err(|error| KeychainError::InvalidKeypairName {
            name: name.as_ref().to_string(),
            error,
        })
    }

    fn load(dir: impl AsRef<Path>, name: impl AsRef<str>) -> Result<Keypair, KeychainError> {
        let name = Keypair::parse_keypair_name(name.as_ref())?;
        let public_path = dir.as_ref().join(name.public_filename());
        let secret_path = dir.as_ref().join(name.secret_filename());
        if public_path.is_file() && secret_path.is_file() {
            let public =
                PublicKey::from_file(public_path).map_err(|error| KeychainError::LoadError {
                    name: name.to_string(),
                    error,
                })?;
            let secret =
                SecretKey::from_file(secret_path).map_err(|e| KeychainError::LoadError {
                    name: name.to_string(),
                    error: e,
                })?;
            Ok(Keypair {
                name,
                public,
                secret,
            })
        } else {
            Err(KeychainError::KeypairNotFound {
                name: name.to_string(),
            })
        }
    }

    fn save(&self, dir: impl AsRef<Path>) -> Result<(), KeychainError> {
        let public_path = dir.as_ref().join(self.name.public_filename());
        let secret_path = dir.as_ref().join(self.name.secret_filename());
        if public_path.is_file() || secret_path.is_file() {
            Err(KeychainError::KeypairAlreadyExists {
                name: self.name.to_string(),
            })
        } else {
            self.public
                .to_file(&public_path)
                .and_then(|()| self.secret.to_file(&secret_path))
                .map_err(|e| KeychainError::SaveError {
                    name: self.name.to_string(),
                    error: e,
                })
        }
    }

    fn delete(&self, dir: impl AsRef<Path>) -> Result<(), KeychainError> {
        let public_path = dir.as_ref().join(self.name.public_filename());
        let secret_path = dir.as_ref().join(self.name.secret_filename());
        let public_result = if public_path.is_file() {
            fs::remove_file(public_path)
        } else {
            Ok(())
        };
        let secret_result = if secret_path.is_file() {
            fs::remove_file(secret_path)
        } else {
            Ok(())
        };

        public_result
            .and(secret_result)
            .map_err(|error| KeychainError::DeleteError {
                name: self.name.to_string(),
                error,
            })
    }
}

/// Pre-verified name for keypairs.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct KeypairName(String);

impl KeypairName {
    fn public_filename(&self) -> String {
        format!("{}.pub", self.0)
    }

    fn secret_filename(&self) -> String {
        format!("{}.sec", self.0)
    }
}

impl AsRef<str> for KeypairName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for KeypairName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl KeypairName {
    /// Create a new KeypairName, returning an error if it doesn't follow
    /// naming rules.
    pub fn new(name: impl AsRef<str>) -> Result<KeypairName, InvalidKeypairName> {
        fn is_invalid_char(c: char) -> bool {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => false,
                _ => true,
            }
        }

        if name.as_ref().is_empty() {
            Err(InvalidKeypairName::Empty)
        } else if let Some(invalid_char) = name.as_ref().chars().find(|c| is_invalid_char(*c)) {
            Err(InvalidKeypairName::BadChar(invalid_char))
        } else {
            Ok(KeypairName(name.as_ref().to_string()))
        }
    }
}

impl FromStr for KeypairName {
    type Err = InvalidKeypairName;

    fn from_str(s: &str) -> Result<KeypairName, InvalidKeypairName> {
        KeypairName::new(s)
    }
}

/// Iterator over keypairs available in a keychain.
pub struct KeychainIter {
    name_iter: Box<dyn Iterator<Item = String>>,
    root_path: PathBuf,
}

impl KeychainIter {
    fn new(root_path: impl AsRef<Path>) -> Result<KeychainIter, KeychainError> {
        let owned_root_path = root_path.as_ref().to_path_buf();
        let name_iter = fs::read_dir(&owned_root_path)
            .map_err(|e| KeychainError::BadKeychainDir {
                error: e,
                path: owned_root_path.clone(),
            })?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let ext = Self::ext_or_empty(&path);
                if ext == "pub" || ext == "sec" {
                    Some(path)
                } else {
                    None
                }
            })
            .filter_map(|path| {
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(String::from)
            })
            .collect::<HashSet<String>>()
            .into_iter();
        Ok(KeychainIter {
            name_iter: Box::new(name_iter),
            root_path: owned_root_path,
        })
    }

    fn ext_or_empty(path: &PathBuf) -> &str {
        path.extension()
            .map(|ext| ext.to_str().unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Iterator for KeychainIter {
    type Item = Keypair;

    fn next(&mut self) -> Option<Keypair> {
        loop {
            if let Some(name) = self.name_iter.next() {
                if let Ok(keypair) = Keypair::load(&self.root_path, name) {
                    return Some(keypair);
                }
            } else {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Keychain;

    use assert_fs::prelude::*;
    use predicates::prelude::*;
    use saltlick;

    fn setup() -> (Keychain, assert_fs::TempDir) {
        let temp = assert_fs::TempDir::new().unwrap();
        let keychain = Keychain::open_at(temp.path()).unwrap();
        (keychain, temp)
    }

    #[test]
    fn crud_keypair_test() {
        let (keychain, temp) = setup();
        let (public, secret) = saltlick::gen_keypair();
        keychain
            .create("test_keypair", public.clone(), secret.clone())
            .unwrap();
        temp.child("test_keypair.pub")
            .assert(predicate::path::is_file());
        temp.child("test_keypair.sec")
            .assert(predicate::path::is_file());

        // Create more key so we're not searching over a problem space of 1.
        for i in 0..10 {
            let (public, secret) = saltlick::gen_keypair();
            keychain
                .create(format!("keypair_{}", i), public, secret)
                .unwrap();
        }

        // Retrieve the keypair directly by name.
        let keypair = keychain.get("test_keypair").unwrap();
        assert_eq!(&public, keypair.public());
        assert_eq!(&secret, keypair.secret());

        // Retrieve keypair by existing public key.
        let keypair = keychain.find(&public).unwrap();
        assert_eq!(&public, keypair.public());
        assert_eq!(&secret, keypair.secret());

        // Check that the keypair exists in listing.
        let found = keychain
            .iter()
            .unwrap()
            .map(|keypair| keypair.name().to_string())
            .find(|name| name == "test_keypair");
        assert_eq!(found, Some(String::from("test_keypair")));

        // Rename the keypair and get it again.
        keychain.rename("test_keypair", "renamed_keypair").unwrap();
        let keypair = keychain.get("renamed_keypair").unwrap();
        assert_eq!(&public, keypair.public());
        assert_eq!(&secret, keypair.secret());
        temp.child("test_keypair.pub")
            .assert(predicate::path::missing());
        temp.child("test_keypair.sec")
            .assert(predicate::path::missing());
        temp.child("renamed_keypair.pub")
            .assert(predicate::path::is_file());
        temp.child("renamed_keypair.sec")
            .assert(predicate::path::is_file());

        // Remove the keypair.
        keychain.remove("renamed_keypair").unwrap();
        keychain.get("renamed_keypair").unwrap_err();
        temp.child("renamed_keypair.pub")
            .assert(predicate::path::missing());
        temp.child("renamed_keypair.sec")
            .assert(predicate::path::missing());
    }
}
