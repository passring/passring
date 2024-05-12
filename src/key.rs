pub mod public {
    use curve25519_dalek::constants;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;

    use serde::{Deserialize, Serialize};

    use super::private::PrivateKey;

    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PublicKey(#[serde(with = "hex::serde")] [u8; 32]);

    impl From<RistrettoPoint> for PublicKey {
        fn from(point: RistrettoPoint) -> Self {
            let compressed = point.compress();
            let key = compressed.as_bytes();
            PublicKey(*key)
        }
    }

    impl Into<RistrettoPoint> for PublicKey {
        fn into(self) -> RistrettoPoint {
            let compressed = CompressedRistretto::from_slice(&self.0).unwrap();
            compressed.decompress().unwrap()
        }
    }

    impl From<PrivateKey> for PublicKey {
        fn from(private_key: PrivateKey) -> Self {
            let scalar: Scalar = private_key.into();
            PublicKey::from(&scalar * constants::RISTRETTO_BASEPOINT_TABLE)
        }
    }

    impl hex::ToHex for PublicKey {
        fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
            self.0.encode_hex()
        }

        fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
            self.0.encode_hex_upper()
        }
    }

    impl hex::FromHex for PublicKey {
        type Error = hex::FromHexError;

        fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
            let key = <[u8; 32] as hex::FromHex>::from_hex(hex)?;
            Ok(PublicKey(key))
        }
    }

    impl crate::traits::Random for PublicKey {
        fn random<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
            let point = RistrettoPoint::random(rng);
            PublicKey::from(point)
        }
    }
}

pub mod private {
    use curve25519_dalek::scalar::Scalar;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PrivateKey {
        #[serde(with = "hex::serde")]
        pub key: [u8; 32],
    }

    impl From<Scalar> for PrivateKey {
        fn from(scalar: Scalar) -> Self {
            let key = scalar.to_bytes();
            PrivateKey { key }
        }
    }

    impl Into<Scalar> for PrivateKey {
        fn into(self) -> Scalar {
            Scalar::from_canonical_bytes(self.key).unwrap()
        }
    }

    impl hex::ToHex for PrivateKey {
        fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
            self.key.encode_hex()
        }

        fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
            self.key.encode_hex_upper()
        }
    }

    impl hex::FromHex for PrivateKey {
        type Error = hex::FromHexError;

        fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
            let key = <[u8; 32] as hex::FromHex>::from_hex(hex)?;
            Ok(PrivateKey { key })
        }
    }

    impl crate::traits::Random for PrivateKey {
        fn random<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
            let scalar = Scalar::random(rng);
            PrivateKey::from(scalar)
        }
    }
}
