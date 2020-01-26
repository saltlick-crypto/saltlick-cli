// Copyright (c) 2020, Nick Stevens <nick@bitcurry.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/license/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::path::PathBuf;

use structopt::StructOpt;

/// File and stream operations on saltlick format files.
#[derive(Debug, StructOpt)]
#[structopt(name = "saltlick")]
pub struct Cli {
    #[structopt(subcommand)]
    pub cmd: Command,
}

impl Cli {
    pub fn from_args() -> Cli {
        <Self as StructOpt>::from_args()
    }
}

#[derive(Debug, StructOpt)]
pub enum Command {
    /// Decrypt an encrypted file.
    #[structopt(name = "decrypt")]
    Decrypt(DecryptArgs),

    /// Encrypt a file or stream.
    #[structopt(name = "encrypt")]
    Encrypt(EncryptArgs),

    /// Generate new key files.
    #[structopt(name = "generate")]
    Generate(GenerateArgs),

    /// Interact with stored keys.
    #[structopt(name = "keychain")]
    Keychain(KeychainArgs),
}

#[derive(Debug, StructOpt)]
pub struct DecryptArgs {
    /// Overwrite existing output file without warning.
    #[structopt(short, long)]
    pub force: bool,

    /// Specify input file (stdin by default).
    #[structopt(short, long, parse(from_os_str))]
    pub infile: Option<PathBuf>,

    /// Specify name of the key (in the keychain) to use to decrypt.
    ///
    /// Specify that only the provided keychain key is to be tried. By default
    /// saltlick looks for an existing keychain keypair that matches the public
    /// key that was used to encrypt the input.
    #[structopt(short, long)]
    pub key: Option<String>,

    /// Specify path to a public keyfile to use to decrypt. Requires that
    /// `-s/--secret` is also provided.
    #[structopt(short, long, parse(from_os_str))]
    pub public: Option<PathBuf>,

    /// Specify path to a secret keyfile to use to decrypt. Requires that
    /// `-p/--public` is also provided.
    #[structopt(short, long, parse(from_os_str))]
    pub secret: Option<PathBuf>,

    /// Specify output file (stdout by default).
    #[structopt(short, long, parse(from_os_str))]
    pub outfile: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
pub struct EncryptArgs {
    /// Overwrite existing output file without warning.
    #[structopt(short, long)]
    pub force: bool,

    /// Specify input file (stdin by default).
    #[structopt(short, long, parse(from_os_str))]
    pub infile: Option<PathBuf>,

    /// Specify name of the key (in the keychain) to use to encrypt. Either
    /// this or `-p/--public` are required.
    #[structopt(short, long)]
    pub key: Option<String>,

    /// Specify path to a public keyfile to use to encrypt. Either this or
    /// `-k/--key` are required.
    #[structopt(short, long, parse(from_os_str))]
    pub public: Option<PathBuf>,

    /// Specify output file (stdout by default).
    #[structopt(short, long, parse(from_os_str))]
    pub outfile: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
pub struct GenerateArgs {
    /// Name of output public key file (default public.pem).
    #[structopt(short, long, parse(from_os_str))]
    pub public: Option<PathBuf>,

    /// Name of output secret key file (default secret.pem).
    #[structopt(short, long, parse(from_os_str))]
    pub secret: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
pub enum KeychainArgs {
    /// Export existing keypair entry to files.
    #[structopt(name = "export")]
    Export {
        /// Name of the keypair to export.
        name: String,

        /// Name of output public key file (default <name>.pub.pem).
        #[structopt(short, long, parse(from_os_str))]
        public: Option<PathBuf>,

        /// Name of output secret key file (default <name>.sec.pem).
        #[structopt(short, long, parse(from_os_str))]
        secret: Option<PathBuf>,
    },

    /// Create a new keypair and store it in the keychain.
    #[structopt(name = "generate")]
    Generate {
        /// Keypair name.
        name: String,
    },

    /// Import existing public/secret key files into keychain.
    #[structopt(name = "import")]
    Import {
        /// Keypair name.
        name: String,

        /// Path to public keyfile.
        public: PathBuf,

        /// Path to secret keyfile.
        secret: PathBuf,
    },

    /// List all keypairs in the keychain.
    #[structopt(name = "list")]
    List,

    /// Remove the specified keypair from the keychain.
    #[structopt(name = "remove")]
    Remove {
        /// Keypair name.
        name: String,
    },

    /// Rename the specified keypair.
    #[structopt(name = "rename")]
    Rename {
        /// Existing keypair name.
        old_name: String,

        /// New keypair name.
        new_name: String,
    },
}
