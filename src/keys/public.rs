use crate::{keys::PrivateKey, traits::random::Random};
use curve25519_dalek::{constants, ristretto::CompressedRistretto, RistrettoPoint};
use hex::ToHex;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub point: RistrettoPoint,
}

impl ToHex for PublicKey {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.point.compress().to_bytes().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.point.compress().to_bytes().encode_hex_upper()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.encode_hex::<String>())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let bytes_vec = hex::decode(str).map_err(serde::de::Error::custom)?;
        let mut bytes = [0u8; 32];
        if bytes_vec.len() != 32 {
            return Err(serde::de::Error::custom("invalid public key, not 32 bytes"));
        }
        bytes.copy_from_slice(&bytes_vec);
        let compressed_key =
            CompressedRistretto::from_slice(&bytes).map_err(serde::de::Error::custom)?;

        let point = compressed_key.decompress();
        if point.is_none() {
            return Err(serde::de::Error::custom("invalid public key, not in field"));
        }
        Ok(PublicKey {
            point: point.unwrap(),
        })
    }
}

impl From<RistrettoPoint> for PublicKey {
    fn from(key: RistrettoPoint) -> Self {
        PublicKey { point: key }
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(private_key: &PrivateKey) -> Self {
        PublicKey {
            point: &private_key.key * constants::RISTRETTO_BASEPOINT_TABLE,
        }
    }
}

impl Random for PublicKey {
    fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRngCore,
    {
        PublicKey {
            point: RistrettoPoint::random(rng),
        }
    }
}
