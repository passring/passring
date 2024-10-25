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

//! # Passring choices
 
use serde::{Deserialize, Serialize};

/// Voting choice
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum VotingChoice {
    /// Basic voting
    Basic(BasicVoting),
    /// Single choice voting
    SingleChoice(SingleChoiceVoting),
    /// Approval voting
    Approval(ApprovalVoting),
    /// Rated voting
    Rated(RatedVoting),
    /// Ranked choice voting (Instant-runoff voting)
    RankedChoice(RankedChoiceVoting),
}


/// Basic voting
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum BasicVoting {
    /// Vote for
    For,
    /// Vote against
    Against,
    /// Abstain
    Abstain,
}

/// Single choice voting
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SingleChoiceVoting {
    /// Choice
    pub choice: String,
}

/// Approval voting
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ApprovalVoting {
    /// Approved choices
    pub choices: Vec<String>,
}

/// Rated voting
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RatedVoting {
    /// Choices
    pub choices: Vec<String>,
    /// Ratings
    pub ratings: Vec<u8>,
}

/// Ranked choice voting (Instant-runoff voting)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RankedChoiceVoting {
    /// Choices in order of preference
    pub choices: Vec<String>,
}
