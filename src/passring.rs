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

//! Main module of the library
//! 
//! This module contains the main structures and functions of the library.

use crate::errors::PassringError::{
    InvalidPayload, InvalidSignature, KeyNotFound, VotingIdMismatch,
};
use crate::key::{private::PrivateKey, public::PublicKey};
use crate::signature::FullSignature;
use crate::Result;
use nazgul::traits::{Link, Verify};
use nazgul::{blsag::BLSAG, traits::Sign};
use rand_core::{CryptoRng, RngCore};
use sha3::Keccak512;
use crate::payload::Payload;

/// Passring structure
pub struct Passring {
    /// Voting ID
    pub voting_id: uuid::Uuid,
    /// Public key ring
    pub ring: Vec<PublicKey>,
}

impl Passring {
    /// Create a new passring instance
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::OsRng;
    /// use passring::{Passring, PublicKey};
    /// use uuid::Uuid;
    /// use passring::traits::Random;
    ///
    /// let voting_id = Uuid::new_v4();
    /// let ring = vec![PublicKey::random(&mut OsRng), PublicKey::random(&mut OsRng)];
    /// let passring = Passring::new(voting_id, ring);
    /// ```
    #[must_use]
    pub fn new(voting_id: uuid::Uuid, ring: Vec<PublicKey>) -> Self {
        Passring { voting_id, ring }
    }

    /// Issue a new signature for the payload
    ///
    /// This function issues a new signature for the payload using the BLSAG
    /// algorithm. The signature is generated using the private key of the
    /// signer and the public keys of the other participants in the ring.
    /// 
    /// Make sure that signer's public key is in the [`ring`](Passring::ring).
    /// 
    /// # Errors
    ///
    /// * [`InvalidPayload`]: Payload is invalid
    /// * [`KeyNotFound`]: Corresponding public key not found in the ring
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::OsRng;
    /// use passring::{Passring, PrivateKey, PublicKey};
    /// use passring::payload::ClearPayload;
    /// use passring::traits::Random;
    ///
    /// let voting_id = uuid::Uuid::new_v4();
    /// let private_key = PrivateKey::random(&mut OsRng);
    /// let public_key = PublicKey::from(private_key);
    ///
    /// let ring: Vec<_> = (0..9).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).collect();
    ///
    /// let passring = Passring::new(voting_id, ring);
    ///
    /// let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
    /// let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();
    ///
    /// let full_signature = passring.issue::<OsRng>(payload, private_key).expect("Failed to issue signature");
    /// ```
    pub fn issue<RNG: CryptoRng + RngCore + Default>(
        &self,
        payload: Payload,
        private_key: PrivateKey,
    ) -> Result<FullSignature> {
        let Ok(message) = serde_json::to_string(&payload) else {
            return Err(InvalidPayload);
        };

        // check private key index in ring
        let my_public_key = PublicKey::from(private_key);
        let Some(my_index) = self.ring.iter().position(|x| x == &my_public_key) else {
            return Err(KeyNotFound);
        };

        let ring_copy = self.ring.clone();

        // delete my public key from ring
        let ring_copy: Vec<PublicKey> = ring_copy
            .into_iter()
            .filter(|x| x != &my_public_key)
            .collect();

        let blsag_signature = BLSAG::sign::<Keccak512, RNG>(
            private_key.into(),
            ring_copy.iter().map(|x| (*x).into()).collect(),
            my_index,
            &message.as_bytes().to_vec(),
        );

        Ok(FullSignature::from_blsag(&blsag_signature, payload))
    }

    /// Verify the signature
    ///
    /// This function verifies the signature using the BLSAG algorithm. Take a
    /// note that the payload will not be decrypted in this function, so you
    /// can't validate the payload here. Use [`validate`](Passring::validate) function instead.
    ///
    /// # Errors
    ///
    /// * [`InvalidPayload`]: Payload is invalid
    /// * [`InvalidSignature`]: Signature is invalid
    /// * [`VotingIdMismatch`]: Voting id in the payload mismatches the current voting id
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::OsRng;
    /// use passring::{Passring, PrivateKey, PublicKey};
    /// use passring::payload::ClearPayload;
    /// use passring::traits::Random;
    /// use uuid::Uuid;
    ///
    /// let voting_id = Uuid::new_v4();
    /// let private_key = PrivateKey::random(&mut OsRng);
    /// let public_key = PublicKey::from(private_key);
    ///
    /// let ring: Vec<_> = (0..9).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).collect();
    ///
    /// let passring = Passring::new(voting_id, ring);
    ///
    /// let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
    /// let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();
    ///
    /// let full_signature = passring.issue::<OsRng>(payload.clone(), private_key).expect("Failed to issue signature");
    ///
    /// passring.verify(&full_signature).expect("Failed to verify signature");
    /// ```
    pub fn verify(&self, full_signature: &FullSignature) -> Result<()> {
        let blsag_signature = full_signature.to_blsag(&self.ring)?;

        if full_signature.payload.voting_id != self.voting_id {
            return Err(VotingIdMismatch);
        }
        
        let Ok(message) = serde_json::to_string(&full_signature.payload) else {
            return Err(InvalidPayload);
        };

        if !BLSAG::verify::<Keccak512>(blsag_signature, &message.as_bytes().to_vec()) {
            return Err(InvalidSignature);
        }

        Ok(())
    }

    /// Validate the signature
    ///
    /// This function validates the signature using the BLSAG algorithm. It will
    /// also decrypt the payload and check if the voting id is the same as the
    /// voting id in the signature.
    ///
    /// # Errors
    ///
    /// * [`InvalidPayload`]: Payload is invalid
    /// * [`InvalidSignature`]: Signature is invalid
    /// * [`VotingIdMismatch`]: Voting id in the payload and the signature or current voting id is different
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::OsRng;
    /// use passring::{Passring, PrivateKey, PublicKey};
    /// use passring::payload::ClearPayload;
    /// use passring::traits::Random;
    /// use uuid::Uuid;
    ///
    /// let voting_id = Uuid::new_v4();
    /// let private_key = PrivateKey::random(&mut OsRng);
    /// let public_key = PublicKey::from(private_key);
    ///
    /// let ring: Vec<_> = (0..9).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).collect();
    ///
    /// let passring = Passring::new(voting_id, ring);
    ///
    /// let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
    /// let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();
    ///
    /// let full_signature = passring.issue::<OsRng>(payload.clone(), private_key).expect("Failed to issue signature");
    ///
    /// passring.validate(&full_signature, &[0u8; 32]).expect("Failed to validate signature");
    /// ```
    pub fn validate(&self, full_signature: &FullSignature, key: &[u8]) -> Result<()> {
        self.verify(full_signature)?;

        let decrypted = full_signature.payload.decrypt(key)?;

        if decrypted.voting_id != self.voting_id {
            return Err(VotingIdMismatch);
        }
        
        if decrypted.voting_id != full_signature.payload.voting_id {
            return Err(VotingIdMismatch);
        }

        Ok(())
    }


    /// Link two signatures
    ///
    /// # Errors
    ///
    /// * [`MalformedSignature`](crate::errors::PassringError::MalformedSignature): Signature is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use rand_core::OsRng;
    /// use passring::{Passring, PrivateKey, PublicKey};
    /// use passring::payload::ClearPayload;
    /// use passring::traits::Random;
    /// use uuid::Uuid;
    ///
    /// let voting_id = Uuid::new_v4();
    /// let private_key = PrivateKey::random(&mut OsRng);
    /// let public_key = PublicKey::from(private_key);
    ///
    /// let ring: Vec<_> = (0..9).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).collect();
    ///
    /// let passring = Passring::new(voting_id, ring);
    ///
    /// let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
    /// let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();
    ///
    /// let full_signature = passring.issue::<OsRng>(payload.clone(), private_key).expect("Failed to issue signature");
    /// let full_signature2 = passring.issue::<OsRng>(payload, private_key).expect("Failed to issue signature");
    ///
    /// assert!(passring.link(&full_signature, &full_signature2).unwrap(), "Signatures signed by the same key should be linkable");
    /// ```
    pub fn link(
        &self,
        full_signature_1: &FullSignature,
        full_signature_2: &FullSignature,
    ) -> Result<bool> {
        let blsag_signature_1 = full_signature_1.to_blsag(&self.ring)?;
        let blsag_signature_2 = full_signature_2.to_blsag(&self.ring)?;

        Ok(BLSAG::link(blsag_signature_1, blsag_signature_2))
    }
}


#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use crate::{Passring, PrivateKey, PublicKey};
    use crate::payload::ClearPayload;
    use crate::traits::Random;

    #[test]
    fn test_passring() {
        let voting_id = uuid::Uuid::new_v4();

        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PublicKey::from(private_key);

        let ring: Vec<_> = (0..9).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).collect();

        let passring = Passring::new(voting_id, ring);

        let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
        let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();

        let full_signature = passring.issue::<OsRng>(payload.clone(), private_key).expect("Failed to issue signature");
        let full_signature2 = passring.issue::<OsRng>(payload, private_key).expect("Failed to issue signature");

        passring.validate(&full_signature, &[0u8; 32]).expect("Failed to validate signature");
        passring.validate(&full_signature2, &[0u8; 32]).expect("Failed to validate signature");

        assert!(passring.link(&full_signature, &full_signature2).unwrap(), "Signatures signed by the same key should be linkable");
    }

    #[test]
    fn test_linking() {
        let voting_id = uuid::Uuid::new_v4();

        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PublicKey::from(private_key);

        let private_key2 = PrivateKey::random(&mut OsRng);
        let public_key2 = PublicKey::from(private_key2);

        let ring: Vec<_> = (0..8).map(|_| PublicKey::random(&mut OsRng)).chain(std::iter::once(public_key)).chain(std::iter::once(public_key2)).collect();

        let passring = Passring::new(voting_id, ring);

        let clear_payload = ClearPayload::new_random(voting_id, 0, &mut OsRng);
        let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();

        let full_signature = passring.issue::<OsRng>(payload.clone(), private_key).expect("Failed to issue signature");

        passring.validate(&full_signature, &[0u8; 32]).expect("Failed to validate signature");

        let full_signature2 = passring.issue::<OsRng>(payload.clone(), private_key).expect("Failed to issue signature");

        passring.validate(&full_signature2, &[0u8; 32]).expect("Failed to validate signature");

        let full_signature3 = passring.issue::<OsRng>(payload, private_key2).expect("Failed to issue signature");

        passring.validate(&full_signature3, &[0u8; 32]).expect("Failed to validate signature");

        assert!(passring.link(&full_signature, &full_signature2).unwrap(), "Signatures signed by the same key should be linkable");
        assert!(!passring.link(&full_signature, &full_signature3).unwrap(), "Signatures signed by different keys should not be linkable");
    }
}