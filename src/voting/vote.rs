use crate::keys::PublicKey;
use crate::types::{Challenge, KeyImage, Response};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
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

                let mut vizited: Vec<String> = Vec::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        "voting_id" => {
                            let voting_id_str: String = map.next_value()?;
                            let voting_id_vec =
                                hex::decode(voting_id_str).map_err(serde::de::Error::custom)?;
                            voting_id.copy_from_slice(&voting_id_vec);
                            vizited.push("voting_id".to_string());
                        }
                        "choice_idx" => {
                            choice_idx = map.next_value()?;
                            vizited.push("choice_idx".to_string());
                        }
                        "ring" => {
                            ring = map.next_value()?;
                            vizited.push("ring".to_string());
                        }
                        "challenge" => {
                            challenge = map.next_value()?;
                            vizited.push("challenge".to_string());
                        }
                        "responses" => {
                            responses = map.next_value()?;
                            vizited.push("responses".to_string());
                        }
                        "key_image" => {
                            key_image = map.next_value()?;
                            vizited.push("key_image".to_string());
                        }
                        _ => {
                            return Err(serde::de::Error::custom(
                                "invalid field in vote deserialization",
                            ))
                        }
                    }
                }

                if vizited.len() != 6 {
                    return Err(serde::de::Error::custom(
                        "invalid number of fields in vote deserialization",
                    ));
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
