use core::fmt;
use zeroize::Zeroizing;

use crate::Error;

pub struct Secret256(Zeroizing<[u8; 32]>);

impl Secret256 {
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(Error::from)?;
        Ok(Self::from_bytes(*bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self::from_bytes(*self.0)
    }
}

impl PartialEq for Secret256 {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Eq for Secret256 {}

impl fmt::Debug for Secret256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32([REDACTED])")
    }
}

pub struct SessionKey(Secret256);

impl SessionKey {
    pub(crate) fn from_secret(secret: Secret256) -> Self {
        Self(secret)
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SessionKey {}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(pub(crate) [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GroupId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GroupKeyHandle(pub(crate) [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecipientKeyHandle(pub(crate) [u8; 16]);

pub struct GroupCiphertext {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
