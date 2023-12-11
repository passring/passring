use curve25519_dalek::{RistrettoPoint, Scalar};
use nazgul::traits::Verify;
use nazgul::{blsag::BLSAG, traits::Sign};
use rand::{CryptoRng, Rng};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::Keccak512;

use crate::{
    keys::{PrivateKey, PublicKey},
    types::{Challenge, KeyImage, Response},
};

#[derive(Debug)]
pub struct Vote {
    pub voting_id: [u8; 32],
    pub choice_idx: u8,
    pub ring: Vec<PublicKey>,
    pub challenge: Challenge,
    pub responses: Vec<Response>,
    pub key_image: KeyImage,
}

// implement serde serialization for Vote with hex encoding
impl Serialize for Vote {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("Vote", 6)?;
        state.serialize_field("voting_id", &hex::encode(self.voting_id))?;
        state.serialize_field("choice_idx", &self.choice_idx)?;
        state.serialize_field("ring", &self.ring)?;
        state.serialize_field("challenge", &self.challenge)?;
        state.serialize_field("responses", &self.responses)?;
        state.serialize_field("key_image", &self.key_image)?;
        state.end()
    }
}

// implement serde deserialization for Vote with hex decoding
impl<'de> Deserialize<'de> for Vote {
    fn deserialize<D>(deserializer: D) -> Result<Vote, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct VoteVisitor;

        impl<'de> serde::de::Visitor<'de> for VoteVisitor {
            type Value = Vote;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex-encoded private key")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Vote, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut voting_id = [0u8; 32];
                let mut choice_idx = 0u8;
                let mut ring = Vec::new();
                let mut challenge = Challenge::default();
                let mut responses = Vec::new();
                let mut key_image = KeyImage::default();

                while let Some(key) = map.next_key()? {
                    match key {
                        "voting_id" => {
                            let voting_id_str: String = map.next_value()?;
                            let voting_id_vec =
                                hex::decode(voting_id_str).map_err(serde::de::Error::custom)?;
                            voting_id.copy_from_slice(&voting_id_vec);
                        }
                        "choice_idx" => {
                            choice_idx = map.next_value()?;
                        }
                        "ring" => {
                            ring = map.next_value()?;
                        }
                        "challenge" => {
                            challenge = map.next_value()?;
                        }
                        "responses" => {
                            responses = map.next_value()?;
                        }
                        "key_image" => {
                            key_image = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::custom(
                                "invalid field in vote deserialization",
                            ))
                        }
                    }
                }

                Ok(Vote {
                    voting_id,
                    choice_idx,
                    ring,
                    challenge,
                    responses,
                    key_image,
                })
            }
        }

        deserializer.deserialize_struct("Vote", &[], VoteVisitor)
    }
}

pub struct VotingContext {
    pub voting_id: [u8; 32],
    pub choices: Vec<String>,
    pub keystore: Vec<PublicKey>,
    pub ring_size: usize,
}

impl VotingContext {
    /// Creates a new [`VotingContext`].
    pub fn new(
        voting_id: [u8; 32],
        choices: Vec<String>,
        keystore: Vec<PublicKey>,
        ring_size: usize,
    ) -> Self {
        if ring_size > keystore.len() {
            panic!("ring size cannot be greater than keystore size");
        }
        if ring_size < 2 {
            panic!("ring size cannot be less than 2");
        }
        VotingContext {
            voting_id,
            choices,
            keystore,
            ring_size,
        }
    }

    fn generate_ring<R>(&self, rng: &mut R) -> Vec<PublicKey>
    where
        R: CryptoRng + Rng,
    {
        let mut ring = Vec::with_capacity(self.ring_size);
        for _ in 0..self.ring_size - 1 {
            let idx = rng.gen_range(0..self.keystore.len());
            ring.push(self.keystore[idx].clone());
        }
        ring
    }

    pub fn vote<R>(&self, private_key: PrivateKey, choice_idx: u8, rng: &mut R) -> Vote
    where
        R: CryptoRng + Rng + Default,
    {
        let ring = self.generate_ring(rng);

        let ristretto_ring = ring.iter().map(|pk| pk.point).collect::<Vec<_>>();

        let secret_index = rng.gen_range(0..self.ring_size);

        let message = json!({
            "voting_id": hex::encode(self.voting_id),
            "choice_idx": choice_idx,
        });
        let signature = BLSAG::sign::<Keccak512, R>(
            private_key.key,
            ristretto_ring,
            secret_index,
            &message.to_string().as_bytes().to_vec(),
        );

        let new_ring = signature
            .ring
            .iter()
            .map(|rp| PublicKey::from(*rp))
            .collect::<Vec<_>>();

        Vote {
            voting_id: self.voting_id,
            choice_idx,
            ring: new_ring,
            challenge: Challenge::from(signature.challenge),
            responses: signature
                .responses
                .iter()
                .map(|r| Response::from(*r))
                .collect::<Vec<_>>(),
            key_image: KeyImage::from(signature.key_image),
        }
    }

    pub fn verify(&self, vote: &Vote) -> bool {
        if vote.voting_id != self.voting_id {
            return false;
        }
        if vote.choice_idx >= self.choices.len() as u8 {
            return false;
        }
        if vote.ring.len() != self.ring_size {
            return false;
        }
        if vote.responses.len() != self.ring_size {
            return false;
        }

        let message = json!({
            "voting_id": hex::encode(vote.voting_id),
            "choice_idx": vote.choice_idx,
        });
        let signature = BLSAG {
            ring: vote.ring.iter().map(|pk| pk.point).collect::<Vec<_>>(),
            challenge: Scalar::from(vote.challenge),
            responses: vote
                .responses
                .iter()
                .map(|r| Scalar::from(*r))
                .collect::<Vec<_>>(),
            key_image: RistrettoPoint::from(vote.key_image),
        };

        BLSAG::verify::<Keccak512>(signature, &message.to_string().as_bytes().to_vec())
    }
}
