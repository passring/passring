use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use hex::ToHex;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Challenge(Scalar);

impl From<Scalar> for Challenge {
    fn from(scalar: Scalar) -> Self {
        Challenge(scalar)
    }
}

impl From<Challenge> for Scalar {
    fn from(challenge: Challenge) -> Self {
        challenge.0
    }
}

impl ToHex for Challenge {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.to_bytes().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.to_bytes().encode_hex_upper()
    }
}

impl Serialize for Challenge {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.encode_hex::<String>())
    }
}

impl<'de> serde::Deserialize<'de> for Challenge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let val = String::deserialize(deserializer)?;
        let bytes_vec = hex::decode(val).map_err(serde::de::Error::custom)?;
        if bytes_vec.len() != 32 {
            return Err(serde::de::Error::custom("invalid challenge, not 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        let key = Scalar::from_canonical_bytes(bytes);
        if bool::from(key.is_some()) {
            return Ok(Challenge(key.unwrap()));
        } else {
            return Err(serde::de::Error::custom("invalid challenge, not in field"));
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Response(Scalar);

impl From<Scalar> for Response {
    fn from(scalar: Scalar) -> Self {
        Response(scalar)
    }
}

impl From<Response> for Scalar {
    fn from(response: Response) -> Self {
        response.0
    }
}

impl ToHex for Response {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.to_bytes().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.to_bytes().encode_hex_upper()
    }
}

impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.encode_hex::<String>())
    }
}

impl<'de> serde::Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let val = String::deserialize(deserializer)?;
        let bytes_vec = hex::decode(val).map_err(serde::de::Error::custom)?;
        if bytes_vec.len() != 32 {
            return Err(serde::de::Error::custom("invalid response, not 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        let key = Scalar::from_canonical_bytes(bytes);
        if bool::from(key.is_some()) {
            return Ok(Response(key.unwrap()));
        } else {
            return Err(serde::de::Error::custom("invalid response, not in field"));
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct KeyImage(RistrettoPoint);

impl From<RistrettoPoint> for KeyImage {
    fn from(point: RistrettoPoint) -> Self {
        KeyImage(point)
    }
}

impl From<KeyImage> for RistrettoPoint {
    fn from(key_image: KeyImage) -> Self {
        key_image.0
    }
}

impl ToHex for KeyImage {
    fn encode_hex<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.compress().to_bytes().encode_hex()
    }

    fn encode_hex_upper<T: std::iter::FromIterator<char>>(&self) -> T {
        self.0.compress().to_bytes().encode_hex_upper()
    }
}

impl Serialize for KeyImage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.encode_hex::<String>())
    }
}

impl<'de> serde::Deserialize<'de> for KeyImage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes_vec = hex::decode(value).map_err(serde::de::Error::custom)?;
        if bytes_vec.len() != 32 {
            return Err(serde::de::Error::custom("invalid key image, not 32 bytes"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        let compressed_key =
            CompressedRistretto::from_slice(&bytes).map_err(serde::de::Error::custom)?;

        let point = compressed_key.decompress();
        if bool::from(point.is_none()) {
            return Err(serde::de::Error::custom("invalid key image, not in field"));
        }
        Ok(KeyImage(point.unwrap()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_serialize_deserialize_challenge() {
        use super::Challenge;
        use curve25519_dalek::scalar::Scalar;

        let challenge = Challenge::from(Scalar::from(0u8));
        let str_challenge = serde_json::to_string_pretty(&challenge).unwrap();

        let new_challenge = serde_json::from_str::<Challenge>(&str_challenge);
        assert_eq!(challenge, new_challenge.unwrap());
    }

    #[test]
    fn test_serialize_deserialize_response() {
        use super::Response;
        use curve25519_dalek::scalar::Scalar;

        let response = Response::from(Scalar::from(0u8));
        let str_response = serde_json::to_string_pretty(&response).unwrap();

        let new_response = serde_json::from_str::<Response>(&str_response);
        assert_eq!(response, new_response.unwrap());
    }

    #[test]
    fn test_serialize_deserialize_key_image() {
        use super::KeyImage;
        use curve25519_dalek::ristretto::RistrettoPoint;

        let key_image = KeyImage::from(RistrettoPoint::default());
        let str_key_image = serde_json::to_string_pretty(&key_image).unwrap();

        let new_key_image = serde_json::from_str::<KeyImage>(&str_key_image);
        assert_eq!(key_image, new_key_image.unwrap());
    }

    #[test]
    fn test_serialize_deserialize_challenge_fail() {
        use super::Challenge;
        use curve25519_dalek::scalar::Scalar;

        let challenge = Challenge::from(Scalar::from(0u8));
        let str_challenge = serde_json::to_string_pretty(&challenge).unwrap();

        let new_challenge = serde_json::from_str::<Challenge>(&str_challenge);
        assert_eq!(challenge, new_challenge.unwrap());

        let new_challenge = serde_json::from_str::<Challenge>("\"invalid\"");
        assert!(new_challenge.is_err());
    }
}
