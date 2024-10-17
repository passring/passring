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

//! # Passring keys

/// Public keys
pub mod public {
    use curve25519_dalek::constants;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::scalar::Scalar;

    use super::private::PrivateKey;

    /// Public key
    #[allow(clippy::module_name_repetitions)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicKey(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; 32]);

    impl From<RistrettoPoint> for PublicKey {
        fn from(point: RistrettoPoint) -> Self {
            let compressed = point.compress();
            let key = compressed.as_bytes();
            PublicKey(*key)
        }
    }

    impl From<PublicKey> for RistrettoPoint {
        fn from(val: PublicKey) -> Self {
            let compressed = CompressedRistretto::from_slice(&val.0).unwrap();
            compressed.decompress().unwrap()
        }
    }

    impl From<PrivateKey> for PublicKey {
        fn from(private_key: PrivateKey) -> Self {
            let scalar: Scalar = private_key.into();
            PublicKey::from(&scalar * constants::RISTRETTO_BASEPOINT_TABLE)
        }
    }

    impl crate::traits::Random for PublicKey {
        fn random<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
            let point = RistrettoPoint::random(rng);
            PublicKey::from(point)
        }
    }
}

/// Private keys
pub mod private {
    use curve25519_dalek::scalar::Scalar;

    /// Private key
    #[allow(clippy::module_name_repetitions)]
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PrivateKey(#[cfg_attr(feature = "serde", serde(with = "hex::serde"))] [u8; 32]);

    impl From<Scalar> for PrivateKey {
        fn from(scalar: Scalar) -> Self {
            let key = scalar.to_bytes();
            PrivateKey(key)
        }
    }

    impl From<PrivateKey> for Scalar {
        fn from(val: PrivateKey) -> Self {
            Scalar::from_canonical_bytes(val.0).unwrap()
        }
    }

    impl crate::traits::Random for PrivateKey {
        fn random<R: rand_core::CryptoRngCore>(rng: &mut R) -> Self {
            let scalar = Scalar::random(rng);
            PrivateKey::from(scalar)
        }
    }
}


#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use crate::{PrivateKey, PublicKey};
    use crate::traits::Random;

    #[test]
    fn test_key_randomness() {
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PublicKey::from(private_key);

        let private_key2 = PrivateKey::random(&mut OsRng);
        let public_key2 = PublicKey::from(private_key2);

        assert_ne!(private_key, private_key2);
        assert_ne!(public_key, public_key2);
    }
    
    #[cfg(feature = "serde")]
    #[test]
    fn test_key_serialization() {
        let private_key = PrivateKey::random(&mut OsRng);
        let public_key = PublicKey::from(private_key);

        let serialized_private_key = serde_json::to_string(&private_key).unwrap();
        let serialized_public_key = serde_json::to_string(&public_key).unwrap();

        let deserialized_private_key: PrivateKey = serde_json::from_str(&serialized_private_key).unwrap();
        let deserialized_public_key: PublicKey = serde_json::from_str(&serialized_public_key).unwrap();

        assert_eq!(private_key, deserialized_private_key);
        assert_eq!(public_key, deserialized_public_key);
    }
}