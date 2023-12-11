use crate::keys::{PrivateKey, PublicKey};
use crate::traits::voting::{Issue, Link, Verify};
use crate::types::{Challenge, KeyImage, Response};
use crate::voting::Vote;
use curve25519_dalek::{RistrettoPoint, Scalar};
use nazgul::blsag::BLSAG;
use nazgul::traits::{Link as _, Sign as _, Verify as _};
use rand::{CryptoRng, Rng};
use serde_json::json;
use sha3::Keccak512;

#[derive(Clone, Debug)]
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
}

impl Issue for VotingContext {
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

    fn issue<R>(&self, private_key: PrivateKey, choice_idx: u8, rng: &mut R) -> Vote
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
}

impl Verify for VotingContext {
    fn verify(&self, vote: &Vote) -> bool {
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

impl Link for VotingContext {
    fn link_signatures(vote_1: &Vote, vote_2: &Vote) -> bool {
        let signature_1 = BLSAG {
            ring: vote_1.ring.iter().map(|pk| pk.point).collect::<Vec<_>>(),
            challenge: Scalar::from(vote_1.challenge),
            responses: vote_1
                .responses
                .iter()
                .map(|r| Scalar::from(*r))
                .collect::<Vec<_>>(),
            key_image: RistrettoPoint::from(vote_1.key_image),
        };
        let signature_2 = BLSAG {
            ring: vote_2.ring.iter().map(|pk| pk.point).collect::<Vec<_>>(),
            challenge: Scalar::from(vote_2.challenge),
            responses: vote_2
                .responses
                .iter()
                .map(|r| Scalar::from(*r))
                .collect::<Vec<_>>(),
            key_image: RistrettoPoint::from(vote_2.key_image),
        };

        BLSAG::link(signature_1, signature_2)
    }

    fn link(&self, vote_1: &Vote, vote_2: &Vote) -> bool {
        if vote_1.voting_id != self.voting_id || vote_2.voting_id != self.voting_id {
            return false;
        }

        VotingContext::link_signatures(vote_1, vote_2)
    }
}
