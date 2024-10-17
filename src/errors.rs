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

//! # Passring errors

use thiserror::Error;

/// Passring error type
#[derive(Error, Debug)]
pub enum PassringError {
    /// Something went wrong with the symmetric encryption
    #[error("Corrupted payload or invalid key")]
    SymmetricError,
    /// The payload is invalid
    #[error("Invalid payload")]
    InvalidPayload,
    /// The signature is malformed
    #[error("Malformed signature")]
    MalformedSignature,
    /// The signature is invalid
    #[error("Invalid signature")]
    InvalidSignature,
    /// The voting ID does not match
    #[error("Voting ID does not match")]
    VotingIdMismatch,
    /// The key is not found in the ring
    #[error("Signing key not found in ring")]
    KeyNotFound,
}
