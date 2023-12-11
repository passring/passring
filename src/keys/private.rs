use crate::traits::Random;
use curve25519_dalek::Scalar;
use hex::ToHex;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey {
    pub key: Scalar,
}

impl ToHex for PrivateKey {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.key.to_bytes().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.key.to_bytes().encode_hex_upper()
    }
}

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.encode_hex::<String>())
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let val = String::deserialize(deserializer)?;
        let bytes_vec = hex::decode(val).map_err(serde::de::Error::custom)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        let key = Scalar::from_canonical_bytes(bytes);
        if key.is_none().into() {
            return Err(serde::de::Error::custom(
                "invalid private key, not in field",
            ));
        }
        Ok(PrivateKey { key: key.unwrap() })
    }
}

impl From<Scalar> for PrivateKey {
    fn from(key: Scalar) -> Self {
        PrivateKey { key }
    }
}

impl Random for PrivateKey {
    fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRngCore,
    {
        PrivateKey {
            key: Scalar::random(rng),
        }
    }
}
