use crate::key::{private::PrivateKey, public::PublicKey};
use crate::signature::FullSignature;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::Scalar;
use nazgul::traits::{Link, Verify};
use nazgul::{blsag::BLSAG, traits::Sign};
use serde::{Deserialize, Serialize};
use sha3::digest::generic_array::GenericArray;
use sha3::Keccak512;

pub struct Passring {
    pub voting_id: uuid::Uuid,
    pub ring: Vec<PublicKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub voting_id: uuid::Uuid,
    pub choice: u16,
}

impl Passring {
    pub fn new(voting_id: uuid::Uuid, ring: Vec<PublicKey>) -> Self {
        Passring { voting_id, ring }
    }

    pub fn issue(&self, choice: u16, private_key: PrivateKey) -> FullSignature {
        let payload = Payload {
            voting_id: self.voting_id,
            choice,
        };
        let message = serde_json::to_string(&payload).unwrap();

        let symmetric_key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&symmetric_key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_choice = cipher.encrypt(&nonce, message.as_bytes()).unwrap();

        // check private key index in ring
        let my_public_key = PublicKey::from(private_key.clone());
        let my_index = self.ring.iter().position(|x| x == &my_public_key).unwrap();

        let ring_copy = self.ring.clone();

        // delete my public key from ring
        let ring_copy: Vec<PublicKey> = ring_copy
            .into_iter()
            .filter(|x| x != &my_public_key)
            .collect();

        let blsag_signature = BLSAG::sign::<Keccak512, OsRng>(
            private_key.into(),
            ring_copy.iter().map(|x| (*x).into()).collect(),
            my_index,
            &encrypted_choice,
        );

        let full_signature = FullSignature::from_blsag(
            blsag_signature,
            encrypted_choice.to_vec(),
            nonce.to_vec(),
            symmetric_key.to_vec(),
            self.voting_id,
        );

        full_signature
    }

    pub fn validate(&self, full_signature: FullSignature) -> bool {
        let blsag_signature = full_signature.to_blsag(self.ring.clone());

        if !BLSAG::verify::<Keccak512>(blsag_signature, &full_signature.encrypted) {
            return false;
        }

        let cipher = ChaCha20Poly1305::new_from_slice(full_signature.key.as_slice()).unwrap();
        let nonce = GenericArray::clone_from_slice(&full_signature.nonce);

        let decrypted = cipher
            .decrypt(&nonce, full_signature.encrypted.as_slice())
            .unwrap();
        let payload = serde_json::from_slice::<Payload>(&decrypted).unwrap();

        if payload.voting_id != self.voting_id {
            return false;
        }

        true
    }

    pub fn link(&self, full_signature_1: FullSignature, full_signature_2: FullSignature) -> bool {
        let blsag_signature_1 = full_signature_1.to_blsag(self.ring.clone());
        let blsag_signature_2 = full_signature_2.to_blsag(self.ring.clone());

        BLSAG::link(blsag_signature_1, blsag_signature_2)
    }
}
