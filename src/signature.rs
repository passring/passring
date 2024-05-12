use crate::PublicKey;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use nazgul::blsag::BLSAG;
use serde::{Deserialize, Serialize};
use sha3::digest::generic_array::GenericArray;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullSignature {
    pub voting_id: uuid::Uuid,
    #[serde(with = "hex::serde")]
    pub challenge: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub responses: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub key_image: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub encrypted: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSignature {
    pub voting_id: uuid::Uuid,
    #[serde(with = "hex::serde")]
    pub challenge: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub responses: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub key_image: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub encrypted: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub nonce: Vec<u8>,
}

impl FullSignature {
    pub fn from_blsag(
        blsag: BLSAG,
        encrypted: Vec<u8>,
        nonce: Vec<u8>,
        key: Vec<u8>,
        voting_id: uuid::Uuid,
    ) -> Self {
        let responses: Vec<[u8; 32]> = blsag.responses.iter().map(|x| x.to_bytes()).collect();

        // merge the responses into a single Vec<u8>
        let responses = responses.iter().fold(Vec::new(), |mut acc, x| {
            acc.extend_from_slice(x);
            acc
        });

        FullSignature {
            voting_id,
            challenge: blsag.challenge.to_bytes().to_vec(),
            responses,
            key_image: blsag.key_image.compress().to_bytes().to_vec(),
            encrypted,
            nonce,
            key,
        }
    }

    pub fn to_blsag(&self, ring: Vec<PublicKey>) -> BLSAG {
        let challenge =
            Scalar::from_canonical_bytes((self.challenge.as_slice()).try_into().unwrap()).unwrap();
        // unmerge the responses into a Vec<[u8; 32]>
        let responses: Vec<Scalar> = self
            .responses
            .chunks_exact(32)
            .map(|x| Scalar::from_canonical_bytes(x.try_into().unwrap()).unwrap())
            .collect();
        let key_image = CompressedRistretto::from_slice(&self.key_image)
            .unwrap()
            .decompress()
            .unwrap();

        BLSAG {
            challenge,
            responses,
            ring: ring.iter().map(|x| (*x).into()).collect(),
            key_image,
        }
    }
}

impl From<FullSignature> for PartialSignature {
    fn from(full: FullSignature) -> Self {
        PartialSignature {
            voting_id: full.voting_id,
            challenge: full.challenge,
            responses: full.responses,
            key_image: full.key_image,
            encrypted: full.encrypted,
            nonce: full.nonce,
        }
    }
}

impl FullSignature {
    pub fn from_partial(partial: PartialSignature, key: Vec<u8>) -> Self {
        FullSignature {
            voting_id: partial.voting_id,
            challenge: partial.challenge,
            responses: partial.responses,
            key_image: partial.key_image,
            encrypted: partial.encrypted,
            nonce: partial.nonce,
            key,
        }
    }
}

impl FullSignature {
    pub fn decrypt(&self) -> Option<crate::passring::Payload> {
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_slice()).unwrap();
        let nonce = GenericArray::clone_from_slice(&self.nonce);

        let d = cipher.decrypt(&nonce, self.encrypted.as_slice()).ok()?;
        let payload = serde_json::from_slice::<crate::passring::Payload>(&d).ok()?;
        Some(payload)
    }
}
