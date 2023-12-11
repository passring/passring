use passring::{
    keys::{PrivateKey, PublicKey},
    traits::{Issue, Random},
    voting::{VoteStore, VotingContext},
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

    let mut store = VoteStore::new(context.clone());

    // issue new vote for choice 0
    let vote = context.issue(private_key.clone(), 0, csprng);
    store.add(vote);

    // issue new wote with the same private key
    let linked_vote = context.issue(private_key.clone(), 1, csprng);
    store.add(linked_vote);

    // issue new vote with a different private key
    let unlinked_vote = context.issue(PrivateKey::random(csprng), 1, csprng);
    store.add(unlinked_vote);

    println!("store verity: {}", store.verity()); // false

    let linked = store.find_linked();
    println!("found {} linked votes, deleting..", linked.len()); // 2

    store.delete(&linked[0]);
    println!("store verity: {}", store.verity()); // true
}
