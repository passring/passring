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

//! Passring signature

use crate::errors::PassringError::{MalformedSignature};
use crate::payload::{Payload};
use crate::{PublicKey, Result};
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use nazgul::blsag::BLSAG;

/// Full signature, representing the voter's signed ballot
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FullSignature {
    /// bLSAG's challenge
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))]
    pub challenge: Vec<u8>,
    /// bLSAG's responses
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))]
    pub responses: Vec<u8>,
    /// bLSAG's key image
    #[cfg_attr(feature = "serde", serde(with = "hex::serde"))]
    pub key_image: Vec<u8>,
    /// Encrypted payload
    pub payload: Payload,
}

impl FullSignature {
    /// Create a new `FullSignature` from a BLSAG and a Payload
    pub fn from_blsag(blsag: &BLSAG, payload: Payload) -> Self {
        let responses: Vec<[u8; 32]> = blsag.responses.iter().map(Scalar::to_bytes).collect();

        let responses: Vec<u8> = responses.iter().flat_map(|x| x.iter()).copied().collect();

        FullSignature {
            challenge: blsag.challenge.to_bytes().to_vec(),
            responses,
            key_image: blsag.key_image.compress().to_bytes().to_vec(),
            payload,
        }
    }

    /// Convert the `FullSignature` to a BLSAG
    ///
    /// # Errors
    ///
    /// * [`MalformedSignature`]: The signature is malformed.
    pub fn to_blsag(&self, ring: &[PublicKey]) -> Result<BLSAG> {
        let Ok(challenge_bytes) = self.challenge.as_slice().try_into() else {
            return Err(MalformedSignature);
        };

        let Some(challenge) = Scalar::from_canonical_bytes(challenge_bytes).into() else {
            return Err(MalformedSignature);
        };

        if self.responses.len() % 32 != 0 {
            return Err(MalformedSignature);
        }

        let mut responses_unwrap_err = false;

        // unmerge the responses into a Vec<[u8; 32]>
        let responses: Vec<Scalar> = self
            .responses
            .clone()
            .chunks_exact(32)
            .map(|x| {
                let bytes = if let Ok(b) = x.try_into() {
                    b
                } else {
                    responses_unwrap_err = true;
                    [0u8; 32]
                };
                if let Some(s) = Scalar::from_canonical_bytes(bytes).into() {
                    s
                } else {
                    responses_unwrap_err = true;
                    Scalar::default()
                }
            })
            .collect();

        if responses_unwrap_err {
            return Err(MalformedSignature);
        }

        let Ok(key_image_uncompressed) = CompressedRistretto::from_slice(&self.key_image) else {
            return Err(MalformedSignature);
        };

        let Some(key_image) = key_image_uncompressed.decompress() else {
            return Err(MalformedSignature);
        };

        Ok(BLSAG {
            challenge,
            responses,
            ring: ring.iter().map(|x| (*x).into()).collect(),
            key_image,
        })
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::RistrettoPoint;
    use nazgul::traits::Sign;
    use super::*;
    use rand_core::OsRng;
    use sha3::Keccak512;
    use crate::choices::{BasicVoting, VotingChoice};
    use crate::payload::ClearPayload;
    use crate::PrivateKey;

    #[test]
    fn test_full_signature() {
        let private_key = Scalar::random(&mut OsRng);

        let ring: Vec<_> = (0..9).map(|_| RistrettoPoint::random(&mut OsRng)).collect();
        let choice = VotingChoice::Basic(BasicVoting::For);


        let clear_payload = ClearPayload::new_random(uuid::Uuid::new_v4(), choice, &mut OsRng);
        let payload = clear_payload.encrypt(&[0u8; 32], &mut OsRng).unwrap();

        let blsag_signature = BLSAG::sign::<Keccak512, OsRng>(
            private_key,
            ring.clone(),
            0,
            &serde_json::to_vec(&payload).unwrap(),
        );

        let full_signature = FullSignature::from_blsag(&blsag_signature, payload.clone());

        let mut ring2: Vec<PublicKey> = ring.iter().map(|x| PublicKey::from(*x)).collect();

        let my_public_key = PublicKey::from(PrivateKey::from(private_key));
        let my_index = 0;
        ring2.insert(my_index, my_public_key);

        let blsag_signature_2 = full_signature.to_blsag(&ring2).unwrap();

        assert_eq!(blsag_signature.challenge, blsag_signature_2.challenge, "Challenge mismatch");
        assert_eq!(blsag_signature.responses, blsag_signature_2.responses, "Responses mismatch");
        assert_eq!(blsag_signature.key_image, blsag_signature_2.key_image, "Key image mismatch");
        assert_eq!(blsag_signature.ring, blsag_signature_2.ring, "Ring mismatch");
    }
}