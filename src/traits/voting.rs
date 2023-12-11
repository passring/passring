use crate::keys::{PrivateKey, PublicKey};
use crate::voting::Vote;
use rand::{CryptoRng, Rng};

pub trait Issue {
    fn generate_ring<R>(&self, rng: &mut R) -> Vec<PublicKey>
    where
        R: CryptoRng + Rng;
    fn issue<R>(&self, private_key: PrivateKey, choice_idx: u8, rng: &mut R) -> Vote
    where
        R: CryptoRng + Rng + Default;
}

pub trait Verify {
    fn verify(&self, vote: &Vote) -> bool;
}

pub trait Link {
    fn link_signatures(vote_1: &Vote, vote_2: &Vote) -> bool;
    fn link(&self, vote_1: &Vote, vote_2: &Vote) -> bool;
}
