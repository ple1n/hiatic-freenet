use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::Secret256;

pub struct Ed25519Signer(SigningKey);

impl Ed25519Signer {
    pub fn from_seed(seed: &Secret256) -> Self {
        Self(SigningKey::from_bytes(seed.expose()))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }

    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        verifying_key
            .verify(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}
