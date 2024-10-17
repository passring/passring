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

//! Passring payloads

use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::generic_array::GenericArray;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use crate::errors::PassringError::{InvalidPayload, SymmetricError};
use crate::Result;

/// Encrypted payload
/// 
/// Only encrypted payload can be used for signing, and transferring over the network.
/// The payload is encrypted using the `ChaCha20Poly1305` algorithm.
#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    /// Voting ID
    pub voting_id: uuid::Uuid,
    /// Encrypted payload
    pub encrypted: Vec<u8>,
    /// Nonce
    pub nonce: Vec<u8>,
}

/// Clear payload
/// 
/// Clear payload is the decrypted version of the payload.
/// Agency will decrypt the payload using the key, received from voter after the ballot is published.
#[allow(clippy::module_name_repetitions)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClearPayload {
    /// Voting ID
    pub voting_id: uuid::Uuid,
    /// Choice
    pub choice: u16,
    /// Randomness. It is used for mitigating brute force attacks.
    pub randomness: Vec<u8>,
}


impl Payload {
    /// Create a new Payload
    ///
    /// # Examples
    ///
    /// ```
    /// use passring::payload::Payload;
    ///
    /// let voting_id = uuid::Uuid::new_v4();
    /// let encrypted = vec![0u8; 32];
    /// let nonce = vec![0u8; 12];
    ///
    /// let payload = Payload::new(voting_id, encrypted, nonce);
    /// ```
    #[must_use]
    pub fn new(voting_id: uuid::Uuid, encrypted: Vec<u8>, nonce: Vec<u8>) -> Self {
        Payload {
            voting_id,
            encrypted,
            nonce,
        }
    }

    /// Decrypt the payload
    ///
    /// # Errors
    ///
    /// * [`SymmetricError`]: Symmetric decryption error
    /// * [`InvalidPayload`]: Payload is invalid
    /// 
    /// # Examples
    ///
    /// ```
    /// use passring::payload::Payload;
    ///
    /// let voting_id = uuid::Uuid::new_v4();
    /// let encrypted = vec![0u8; 32];
    /// let nonce = vec![0u8; 12];
    ///
    /// let payload = Payload::new(voting_id, encrypted, nonce);
    ///
    /// let key = vec![0u8; 32];
    ///
    /// let decrypted = payload.decrypt(&key);
    ///
    /// // We used zeroed values for the payload and key, so the decryption will fail
    /// assert!(decrypted.is_err());
    /// ```
    pub fn decrypt(&self, key: &[u8]) -> Result<ClearPayload> {
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key) else {
            return Err(SymmetricError);
        };

        let nonce = GenericArray::clone_from_slice(&self.nonce);

        let Ok(d) = cipher.decrypt(&nonce, self.encrypted.as_slice()) else {
            return Err(SymmetricError);
        };
        match serde_json::from_slice::<ClearPayload>(&d) {
            Ok(payload) => Ok(payload),
            Err(_) => Err(InvalidPayload),
        }
    }
}

impl ClearPayload {

    /// Create a new `ClearPayload`
    ///
    /// This function creates a new `ClearPayload` with the given `voting_id`, `choice` and `randomness`.
    /// Randomness is a random vector of bytes, and primarily used for mitigating brute force attacks.
    /// For production use, the randomness should be generated using a secure random number generator.
    /// See [`new_random`](ClearPayload::new_random) for generating `ClearPayload` with prefilled randomness.
    ///
    /// # Examples
    ///
    /// ```
    /// use passring::payload::ClearPayload;
    ///
    /// let voting_id = uuid::Uuid::new_v4();
    /// let choice = 0;
    /// let randomness = vec![0u8; 32]; // must be random bytes
    ///
    /// let payload = ClearPayload::new(voting_id, choice, randomness);
    /// ```
    #[must_use]
    pub fn new(voting_id: uuid::Uuid, choice: u16, randomness: Vec<u8>) -> Self {
        ClearPayload {
            voting_id,
            choice,
            randomness,
        }
    }

    /// Create a new `ClearPayload` with random values
    ///
    /// This function creates a new `ClearPayload` with the given `voting_id`, `choice` and random `randomness`.
    /// Randomness is a random vector of bytes, and primarily used for mitigating brute force attacks.
    /// In this function, the randomness is generated using the given `rng`.
    ///
    /// # Examples
    ///
    /// ```
    /// use passring::payload::ClearPayload;
    /// use rand_core::OsRng;
    ///
    /// let voting_id = uuid::Uuid::new_v4();
    /// let choice = 0;
    ///
    /// let payload = ClearPayload::new_random(voting_id, choice, &mut OsRng);
    /// ```
    pub fn new_random(voting_id: uuid::Uuid, choice: u16, rng: &mut impl CryptoRngCore) -> Self {
        let mut randomness = vec![0u8; 32];
        rng.fill_bytes(&mut randomness);
        ClearPayload::new(voting_id, choice, randomness)
    }

    /// Encrypt the payload
    /// 
    /// This function encrypts the payload using the given `key` and `rng`.
    /// The encryption is done using the `ChaCha20Poly1305` algorithm.
    /// Nonce is generated using the given `rng`.
    /// 
    /// # Errors
    /// 
    /// * [`SymmetricError`]: Symmetric encryption error
    /// * [`InvalidPayload`]: Payload is invalid
    /// 
    /// # Examples 
    /// 
    /// ```
    /// use passring::payload::ClearPayload;
    /// use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    /// use rand_core::OsRng;
    ///
    /// let voting_id = uuid::Uuid::new_v4();
    /// let choice = 0;
    ///
    /// let clear_payload = ClearPayload::new_random(voting_id, choice, &mut OsRng);
    /// let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    ///
    /// let payload = clear_payload.encrypt(&key, &mut OsRng).unwrap();
    /// ```
    pub fn encrypt<R: CryptoRngCore>(&self, key: &[u8], rng: &mut R) -> Result<Payload> {
        let Ok(cipher) = ChaCha20Poly1305::new_from_slice(key) else {
            return Err(SymmetricError);
        };

        let nonce = ChaCha20Poly1305::generate_nonce(rng);

        let Ok(message) = serde_json::to_vec(&self) else {
            return Err(InvalidPayload);
        };

        let Ok(e) = cipher.encrypt(&nonce, message.as_slice()) else {
            return Err(SymmetricError);
        };

        Ok(Payload {
            voting_id: self.voting_id,
            encrypted: e,
            nonce: nonce.to_vec(),
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_payload() {
        let voting_id = uuid::Uuid::new_v4();
        let clear_payload = ClearPayload::new(voting_id, 0, vec![0u8; 32]);
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let payload = clear_payload.encrypt(&key, &mut OsRng).unwrap();
        let decrypted = payload.decrypt(&key).unwrap();
        assert_eq!(clear_payload, decrypted);
    }

    #[test]
    fn test_payload_random() {
        let voting_id = uuid::Uuid::new_v4();
        let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let payload = clear_payload.encrypt(&key, &mut OsRng).unwrap();
        let decrypted = payload.decrypt(&key).unwrap();
        assert_eq!(clear_payload, decrypted);
    }
}