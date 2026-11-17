use std::{fmt, io::Read};

use bincode::Options;
use bzip2::read::BzDecoder;
use cairo_air::{
    CairoProofForRustVerifier,
    utils::{VerificationOutput, get_verification_output},
    verifier::verify_cairo_ex,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use stwo::core::{channel::MerkleChannel, vcs_lifted::blake2_merkle::Blake2sMerkleChannel};

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub version: u8,
    pub proof: Vec<u8>,
}

impl Candidate {
    pub fn new(proof: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            proof,
        }
    }

    pub fn from_proof_bytes(proof: &[u8]) -> Self {
        Self::new(proof.to_vec())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, VerificationError> {
        encode_binary(self)
            .map_err(|error| VerificationError::InvalidCandidateEncoding(error.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerificationError> {
        decode_binary(bytes)
            .map_err(|error| VerificationError::InvalidCandidateEncoding(error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractParameters {
    pub version: u8,
    pub program_hash: String,
    pub public_output: Vec<String>,
}

impl ContractParameters {
    pub fn new(program_hash: String, public_output: Vec<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            program_hash,
            public_output,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, VerificationError> {
        encode_binary(self)
            .map_err(|error| VerificationError::InvalidParametersEncoding(error.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerificationError> {
        decode_binary(bytes)
            .map_err(|error| VerificationError::InvalidParametersEncoding(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOutput {
    pub program_hash: String,
    pub public_output: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    UnsupportedCandidateVersion { actual: u8, expected: u8 },
    UnsupportedParametersVersion { actual: u8, expected: u8 },
    InvalidCandidateEncoding(String),
    InvalidParametersEncoding(String),
    InvalidCompressedProof(String),
    InvalidSerializedProof(String),
    ProofVerificationFailed(String),
    ProgramHashMismatch,
    PublicOutputMismatch,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCandidateVersion { actual, expected } => {
                write!(
                    f,
                    "unsupported candidate version {actual}; expected {expected}"
                )
            }
            Self::UnsupportedParametersVersion { actual, expected } => {
                write!(
                    f,
                    "unsupported contract parameter version {actual}; expected {expected}"
                )
            }
            Self::InvalidCandidateEncoding(error) => {
                write!(f, "invalid binary candidate: {error}")
            }
            Self::InvalidParametersEncoding(error) => {
                write!(f, "invalid binary contract parameters: {error}")
            }
            Self::InvalidCompressedProof(error) => {
                write!(f, "invalid compressed proof: {error}")
            }
            Self::InvalidSerializedProof(error) => {
                write!(f, "invalid serialized proof: {error}")
            }
            Self::ProofVerificationFailed(error) => {
                write!(f, "Stwo Cairo proof verification failed: {error}")
            }
            Self::ProgramHashMismatch => {
                f.write_str("proof program hash does not match contract parameters")
            }
            Self::PublicOutputMismatch => {
                f.write_str("proof public output does not match contract parameters")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

fn encode_binary<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(value)
}

fn decode_binary<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
}

pub fn inspect_candidate(candidate: &Candidate) -> Result<VerifiedOutput, VerificationError> {
    if candidate.version != PROTOCOL_VERSION {
        return Err(VerificationError::UnsupportedCandidateVersion {
            actual: candidate.version,
            expected: PROTOCOL_VERSION,
        });
    }

    let mut decoder = BzDecoder::new(candidate.proof.as_slice());
    let mut encoded = Vec::new();
    decoder
        .read_to_end(&mut encoded)
        .map_err(|error| VerificationError::InvalidCompressedProof(error.to_string()))?;
    let proof: CairoProofForRustVerifier<<Blake2sMerkleChannel as MerkleChannel>::H> =
        bincode::deserialize(&encoded)
            .map_err(|error| VerificationError::InvalidSerializedProof(error.to_string()))?;

    let output: VerificationOutput =
        get_verification_output(&proof.claim.public_data.public_memory);
    verify_cairo_ex::<Blake2sMerkleChannel>(proof, false)
        .map_err(|error| VerificationError::ProofVerificationFailed(error.to_string()))?;

    Ok(VerifiedOutput {
        program_hash: output.program_hash.to_string(),
        public_output: output.output.iter().map(ToString::to_string).collect(),
    })
}

pub fn verify_candidate(
    candidate: &Candidate,
    parameters: &ContractParameters,
) -> Result<VerifiedOutput, VerificationError> {
    if parameters.version != PROTOCOL_VERSION {
        return Err(VerificationError::UnsupportedParametersVersion {
            actual: parameters.version,
            expected: PROTOCOL_VERSION,
        });
    }
    let output = inspect_candidate(candidate)?;
    if output.program_hash != parameters.program_hash {
        return Err(VerificationError::ProgramHashMismatch);
    }
    if output.public_output != parameters.public_output {
        return Err(VerificationError::PublicOutputMismatch);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{
        Candidate, ContractParameters, PROTOCOL_VERSION, VerificationError, inspect_candidate,
    };

    #[test]
    fn candidate_binary_round_trip_preserves_proof_bytes() {
        let candidate = Candidate::from_proof_bytes(&[0, 1, 2, 255]);
        let encoded = candidate.to_bytes().unwrap();

        assert_eq!(Candidate::from_bytes(&encoded).unwrap(), candidate);
    }

    #[test]
    fn contract_parameters_binary_round_trip() {
        let parameters =
            ContractParameters::new("program-hash".into(), vec!["1".into(), "2".into()]);
        let encoded = parameters.to_bytes().unwrap();

        assert_eq!(
            ContractParameters::from_bytes(&encoded).unwrap(),
            parameters
        );
    }

    #[test]
    fn binary_decoding_rejects_json_and_trailing_bytes() {
        assert!(matches!(
            Candidate::from_bytes(br#"{"version":1,"proof":"00"}"#),
            Err(VerificationError::InvalidCandidateEncoding(_))
        ));

        let mut encoded = Candidate::new(vec![0]).to_bytes().unwrap();
        encoded.push(0);
        assert!(matches!(
            Candidate::from_bytes(&encoded),
            Err(VerificationError::InvalidCandidateEncoding(_))
        ));
    }

    #[test]
    fn rejects_unsupported_candidate_version_before_decoding_proof() {
        let mut candidate = Candidate::new(b"not-a-proof".to_vec());
        candidate.version = PROTOCOL_VERSION + 1;

        assert!(matches!(
            inspect_candidate(&candidate),
            Err(VerificationError::UnsupportedCandidateVersion { .. })
        ));
    }

    #[test]
    fn rejects_invalid_compressed_proof() {
        assert!(matches!(
            inspect_candidate(&Candidate::new(vec![0])),
            Err(VerificationError::InvalidCompressedProof(_))
        ));
    }
}
