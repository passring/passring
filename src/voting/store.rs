use super::{Vote, VotingContext};
use crate::traits::{Link, Verify};

pub struct VoteStore {
    context: VotingContext,
    votes: Vec<Vote>,
}

impl VoteStore {
    pub fn new(context: VotingContext) -> Self {
        Self {
            context,
            votes: Vec::new(),
        }
    }

    pub fn context(&self) -> &VotingContext {
        &self.context
    }

    pub fn votes(&self) -> &[Vote] {
        &self.votes
    }

    pub fn add(&mut self, vote: Vote) {
        self.votes.push(vote);
    }

    pub fn delete(&mut self, vote: &Vote) {
        self.votes.retain(|v| v != vote);
    }

    pub fn extend(&mut self, votes: Vec<Vote>) {
        self.votes.extend(votes);
    }

    pub fn verity(&self) -> bool {
        let verified = self.verify_votes();
        let not_linked = self.check_links();

        verified && not_linked
    }

    pub fn find_linked(&self) -> Vec<Vote> {
        let mut linked = Vec::new();

        for (i, vote_1) in self.votes.iter().enumerate() {
            for vote_2 in self.votes.iter().skip(i + 1) {
                if self.context.link(vote_1, vote_2) {
                    linked.push(vote_1.clone());
                    linked.push(vote_2.clone());
                }
            }
        }

        linked
    }

    fn verify_votes(&self) -> bool {
        self.votes.iter().all(|vote| self.context.verify(vote))
    }

    fn check_links(&self) -> bool {
        // verify that all votes are not linked to each other
        for (i, vote_1) in self.votes.iter().enumerate() {
            for vote_2 in self.votes.iter().skip(i + 1) {
                if self.context.link(vote_1, vote_2) {
                    return false;
                }
            }
        }
        true
    }
}
