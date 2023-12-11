use passring::{
    keys::{PrivateKey, PublicKey},
    traits::Random,
    voting::{Vote, VotingContext},
};

pub fn main() {
    let csprng = &mut rand::thread_rng();
    let private_key = PrivateKey::random(csprng);

    let keystore = (0..100)
        .map(|_| PublicKey::random(csprng))
        .collect::<Vec<_>>();

    let context = VotingContext::new(
        [0u8; 32],
        vec!["Yes".to_string(), "No".to_string()],
        keystore,
        10,
    );

    let vote = context.vote(private_key, 0, csprng);
    let str_vote = serde_json::to_string_pretty(&vote).unwrap();
    println!("Vote: {}", str_vote);

    let new_vote = serde_json::from_str::<Vote>(&str_vote);
    println!("Verified: {}", context.verify(&new_vote.unwrap()));
}
