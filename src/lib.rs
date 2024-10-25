// Copyright (C) 2024 Stanislav Zhevachevskyi
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
// 
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Passring
//! 
//! Cryptographic library for secure voting systems.
//! 
//! Passring is a cryptographic library for secure voting systems. It provides a set of cryptographic primitives for 
//! secure voting systems, including key generation, encryption, decryption, and signature generation.
//! 
//! For more information, see the [Passring whitepaper](https://docs.nau-digital.com/passring/whitepaper).
//! ## Features
//! 
//! - **Secure**: Passring uses the latest cryptographic algorithms to ensure the security of the voting system.
//! - **Fast**: Passring is optimized for performance and can handle large volumes of data.
//! - **Easy to use**: Passring provides a simple and easy-to-use API for developers.
//! 
//! ## Algorithms
//! 
//! Passring uses the following cryptographic algorithms:
//! 
//! - **ChaCha20-Poly1305**: For encryption and decryption of payloads.
//! - **Curve25519 and Ristretto**: For key generation.
//! - **bLSAG**: For signature generation. bLSAG is a ring signature scheme described in the Chapter 3 of [Zero to Monero 2.0 (Z2M2)](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf).
//! 
//! ## Usage
//! 
//! To use Passring in your project, add it as dependency using Cargo:
//! 
//! ```bash
//! cargo add passring
//! ```
//! 
//! NOTE: If you want to serialize and deserialize keys/signatures, you need to enable the `serde` feature:
//! 
//! ```bash
//! cargo add passring --features=serde
//! ```
//! 
//! Here is an example of how to use Passring to create a new voting system:
//! 
//! ```rust
//! use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
//! use passring::{Passring, PrivateKey, PublicKey};
//! use passring::payload::ClearPayload;
//! use passring::traits::Random;
//! use rand_core::OsRng;
//! use passring::choices::{BasicVoting, VotingChoice};
//!
//! // Generate a new voting ID
//! let voting_id = uuid::Uuid::new_v4();
//!
//! // Generate a new private key and public key
//! let private_key = PrivateKey::random(&mut OsRng);
//! let public_key = PublicKey::from(private_key);
//!
//! // Ring must be retrieved from the Verifier
//! let ring: Vec<PublicKey> = (0..9).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).collect();
//!
//! // Create a new Passring instance
//! let passring = Passring::new(voting_id, ring);
//!
//! // Create a new clear payload
//!
//! let choice = VotingChoice::Basic(BasicVoting::For); // The choice of the voter
//! let clear_payload = ClearPayload::new_random(voting_id, choice, &mut OsRng);
//!
//! // Encrypt the clear payload
//! let key = ChaCha20Poly1305::generate_key(&mut OsRng); // Generate a new key
//! let payload = clear_payload.encrypt(&key, &mut OsRng).expect("Failed to encrypt payload");
//!
//! // Issue a new signature
//! let full_signature = passring.issue::<OsRng>(payload, private_key).expect("Failed to issue signature");
//!
//! // Verify the signature
//! passring.verify(&full_signature).expect("Failed to verify signature");
//!
//! // validate the signature (when the key is known)
//! passring.validate(&full_signature, &key).expect("Failed to validate signature");
//!
//! println!("Signature is valid");
//! ```

pub mod errors;
pub mod key;
pub mod passring;
pub mod signature;
pub mod traits;
pub mod payload;
pub mod choices;

pub use crate::key::{private::PrivateKey, public::PublicKey};
pub use crate::passring::Passring;

/// Result type for Passring operations.
type Result<T> = std::result::Result<T, errors::PassringError>;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
