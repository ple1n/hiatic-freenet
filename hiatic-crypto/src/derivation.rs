use crate::{Error, Secret256};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub struct DerivationContext(Vec<u8>);

impl DerivationContext {
    pub fn new(context: impl AsRef<[u8]>) -> Self {
        Self(context.as_ref().to_vec())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct VolatileSecret(Secret256);

impl VolatileSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret256::from_bytes(bytes))
    }

    pub fn generate() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(Error::from)?;
        Ok(Self(Secret256::from_bytes(*bytes)))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

/// Derives a child key from a parent and a stable context.
///
/// Without `volatile`, the parent and context reproduce the key without
/// per-key secret material. HMAC derivation is intended to prevent exposure of
/// a child key from revealing its parent.
///
/// `volatile` adds an independent secret factor. It only adds protection when
/// kept separate from the parent; erasing it prevents re-derivation from the
/// parent and context alone, but cannot revoke copied keys. If relying on it
/// after parent compromise, use an independently generated value with at
/// least 128 bits of entropy.
pub(crate) fn derive(
    parent: &Secret256,
    deterministic: &DerivationContext,
    volatile: Option<&VolatileSecret>,
) -> Secret256 {
    let hashed_parent = Sha256::digest(parent.expose());
    let mut mac =
        HmacSha256::new_from_slice(&hashed_parent).expect("HMAC accepts keys of any length");
    mac.update(b"hiatic-crypto/key-derivation/v1");
    mac.update(&(deterministic.as_bytes().len() as u64).to_be_bytes());
    mac.update(deterministic.as_bytes());

    match volatile {
        Some(secret) => {
            // Distinguish an absent secret from a present all-zero secret.
            mac.update(&[1]);
            mac.update(secret.expose());
        }
        None => mac.update(&[0]),
    }

    Secret256::from_bytes(mac.finalize().into_bytes().into())
}
