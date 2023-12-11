use passring::{
    keys::{PrivateKey, PublicKey},
    traits::{Issue, Link, Random, Verify},
    voting::{Vote, VotingContext},
};

pub fn main() {
    let csprng = &mut rand::thread_rng();

    // generate random primary private key
    let private_key = PrivateKey::random(csprng);

    // generate random keystore
    let keystore = (0..100)
        .map(|_| PublicKey::random(csprng))
        .collect::<Vec<_>>();

    let context = VotingContext::new(
        [0u8; 32],                                 // voting id
        vec!["Yes".to_string(), "No".to_string()], // choices
        keystore,                                  // keystore
        10,                                        // ring size
    );

    // issue new vote for choice 0
    let vote = context.issue(private_key.clone(), 0, csprng);

    // verify vote
    println!("vote is verified: {}", context.verify(&vote));

    // serialize vote to string
    let vote_string = serde_json::to_string_pretty(&vote).unwrap();
    println!("{}", vote_string);

    // deserialize vote from string
    let vote: Vote = serde_json::from_str(&vote_string).unwrap();
    println!(
        "vote after deserialization is verified: {}",
        context.verify(&vote)
    );

    // issue new vote for choice 1 with the same private key
    let vote_2 = context.issue(private_key.clone(), 1, csprng);
    println!("vote2 is verified: {}", context.verify(&vote_2));

    // link votes
    println!(
        "vote and vote2 is signed with same private key: {}",
        context.link(&vote, &vote_2)
    );

    // issue vote 3 with a different private key
    let vote_3 = context.issue(PrivateKey::random(csprng), 0, csprng);
    println!("vote3 is verified: {}", context.verify(&vote_3));

    // link votes
    println!(
        "vote and vote3 is signed with same private key: {}",
        context.link(&vote, &vote_3)
    );
    println!(
        "vote2 and vote3 is signed with same private key: {}",
        context.link(&vote_2, &vote_3)
    );
}
