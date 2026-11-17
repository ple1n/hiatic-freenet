use crate::{Error, Secret256, SessionKey};
use hpke::{
    Deserializable, Kem as KemTrait, Serializable,
    kem::{X25519HkdfSha256, XWing},
    rand_core::SeedableRng,
};
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;

pub trait KeyEncapsulation: Send + Sync {
    /// Encapsulates deterministically for the recipient using `session_key`
    /// as the KEM randomness seed. With the same suite, recipient public key,
    /// and `SessionKey`, this returns the same encapsulation and shared secret.
    fn encapsulate(
        &self,
        recipient_public_key: &[u8],
        session_key: &SessionKey,
    ) -> Result<(Vec<u8>, Secret256), Error>;

    /// Recovers the shared secret from the recipient private key and
    /// encapsulation. The sender's `SessionKey` is not needed for decapsulation.
    fn decapsulate(
        &self,
        recipient_private_key: &[u8],
        encapsulation: &[u8],
    ) -> Result<Secret256, Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpkeSuite {
    X25519,
    XWing,
}

impl HpkeSuite {
    pub(crate) fn id(self) -> u8 {
        match self {
            Self::X25519 => 1,
            Self::XWing => 2,
        }
    }

    fn from_id(id: u8) -> Result<Self, Error> {
        match id {
            1 => Ok(Self::X25519),
            2 => Ok(Self::XWing),
            _ => Err(Error::TransportFailed),
        }
    }
}

pub struct HpkeRecipientKeypair {
    suite: HpkeSuite,
    private_key: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl HpkeRecipientKeypair {
    /// Recreates a recipient keypair from a session key derived by the
    /// recipient's wallet. The session key must remain private to that wallet.
    pub fn from_session_key(suite: HpkeSuite, session_key: &SessionKey) -> Self {
        let (private_key, public_key) = match suite {
            HpkeSuite::X25519 => generate_keypair::<X25519HkdfSha256>(session_key.expose()),
            HpkeSuite::XWing => generate_keypair::<XWing>(session_key.expose()),
        };
        Self {
            suite,
            private_key: Zeroizing::new(private_key),
            public_key,
        }
    }

    pub fn suite(&self) -> HpkeSuite {
        self.suite
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn decapsulate(&self, encapsulation: &[u8]) -> Result<Secret256, Error> {
        HpkeKeyEncapsulation::new(self.suite).decapsulate(&self.private_key, encapsulation)
    }
}

pub struct HpkeKeyEncapsulation {
    suite: HpkeSuite,
}

impl HpkeKeyEncapsulation {
    pub fn new(suite: HpkeSuite) -> Self {
        Self { suite }
    }
}

impl KeyEncapsulation for HpkeKeyEncapsulation {
    fn encapsulate(
        &self,
        recipient_public_key: &[u8],
        session_key: &SessionKey,
    ) -> Result<(Vec<u8>, Secret256), Error> {
        match self.suite {
            HpkeSuite::X25519 => encapsulate::<X25519HkdfSha256>(recipient_public_key, session_key)
                .and_then(|(enc, secret)| Ok((encode_encapsulation(self.suite, &enc)?, secret))),
            HpkeSuite::XWing => encapsulate::<XWing>(recipient_public_key, session_key)
                .and_then(|(enc, secret)| Ok((encode_encapsulation(self.suite, &enc)?, secret))),
        }
    }

    fn decapsulate(
        &self,
        recipient_private_key: &[u8],
        encapsulation: &[u8],
    ) -> Result<Secret256, Error> {
        let (suite, encapped_key) = decode_encapsulation(encapsulation)?;
        if suite != self.suite {
            return Err(Error::TransportFailed);
        }
        match suite {
            HpkeSuite::X25519 => {
                decapsulate::<X25519HkdfSha256>(recipient_private_key, encapped_key)
            }
            HpkeSuite::XWing => decapsulate::<XWing>(recipient_private_key, encapped_key),
        }
    }
}

fn generate_keypair<Kem: KemTrait>(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (private_key, public_key) = Kem::derive_keypair(seed);
    (
        private_key.to_bytes().as_slice().to_vec(),
        public_key.to_bytes().as_slice().to_vec(),
    )
}

fn encapsulate<Kem: KemTrait>(
    recipient_public_key: &[u8],
    session_key: &SessionKey,
) -> Result<(Vec<u8>, Secret256), Error> {
    let public_key =
        Kem::PublicKey::from_bytes(recipient_public_key).map_err(|_| Error::TransportFailed)?;
    // Seeding the KEM RNG from SessionKey makes its encapsulation randomness repeatable.
    let mut rng = ChaCha20Rng::from_seed(*session_key.expose());
    let (shared_secret, encapped_key) =
        Kem::encap_with_rng(&public_key, None, &mut rng).map_err(|_| Error::TransportFailed)?;
    let shared_secret: [u8; 32] = shared_secret
        .0
        .as_slice()
        .try_into()
        .map_err(|_| Error::TransportFailed)?;
    Ok((
        encapped_key.to_bytes().as_slice().to_vec(),
        Secret256::from_bytes(shared_secret),
    ))
}

fn decapsulate<Kem: KemTrait>(
    recipient_private_key: &[u8],
    encapped_key: &[u8],
) -> Result<Secret256, Error> {
    let private_key =
        Kem::PrivateKey::from_bytes(recipient_private_key).map_err(|_| Error::TransportFailed)?;
    let encapped_key =
        Kem::EncappedKey::from_bytes(encapped_key).map_err(|_| Error::TransportFailed)?;
    let shared_secret =
        Kem::decap(&private_key, None, &encapped_key).map_err(|_| Error::TransportFailed)?;
    let shared_secret: [u8; 32] = shared_secret
        .0
        .as_slice()
        .try_into()
        .map_err(|_| Error::TransportFailed)?;
    Ok(Secret256::from_bytes(shared_secret))
}

fn encode_encapsulation(suite: HpkeSuite, encapped_key: &[u8]) -> Result<Vec<u8>, Error> {
    let encapped_len = u16::try_from(encapped_key.len()).map_err(|_| Error::TransportFailed)?;
    let mut envelope = Vec::with_capacity(4 + encapped_key.len());
    envelope.push(1);
    envelope.push(suite.id());
    envelope.extend_from_slice(&encapped_len.to_be_bytes());
    envelope.extend_from_slice(encapped_key);
    Ok(envelope)
}

fn decode_encapsulation(encapsulation: &[u8]) -> Result<(HpkeSuite, &[u8]), Error> {
    let (&version, rest) = encapsulation.split_first().ok_or(Error::TransportFailed)?;
    if version != 1 {
        return Err(Error::TransportFailed);
    }
    let (&suite_id, rest) = rest.split_first().ok_or(Error::TransportFailed)?;
    let suite = HpkeSuite::from_id(suite_id)?;
    let length_bytes: [u8; 2] = rest
        .get(..2)
        .ok_or(Error::TransportFailed)?
        .try_into()
        .map_err(|_| Error::TransportFailed)?;
    let encapped_len = usize::from(u16::from_be_bytes(length_bytes));
    let encapped_end = 2usize
        .checked_add(encapped_len)
        .ok_or(Error::TransportFailed)?;
    let encapped_key = rest.get(2..encapped_end).ok_or(Error::TransportFailed)?;
    if !rest
        .get(encapped_end..)
        .ok_or(Error::TransportFailed)?
        .is_empty()
    {
        return Err(Error::TransportFailed);
    }
    Ok((suite, encapped_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_kem_agrees_on_shared_secret() {
        round_trip(HpkeSuite::X25519);
    }

    #[test]
    fn xwing_kem_agrees_on_shared_secret() {
        round_trip(HpkeSuite::XWing);
    }

    fn round_trip(suite: HpkeSuite) {
        let encapsulation = HpkeKeyEncapsulation::new(suite);
        let recipient_session_key = SessionKey::from_secret(Secret256::from_bytes([18; 32]));
        let recipient = HpkeRecipientKeypair::from_session_key(suite, &recipient_session_key);
        let session_key = SessionKey::from_secret(Secret256::from_bytes([17; 32]));
        let (enc, sender_shared_secret) = encapsulation
            .encapsulate(recipient.public_key_bytes(), &session_key)
            .unwrap();
        let (repeated_enc, repeated_shared_secret) = encapsulation
            .encapsulate(recipient.public_key_bytes(), &session_key)
            .unwrap();
        let receiver_shared_secret = recipient.decapsulate(&enc).unwrap();
        assert_eq!(sender_shared_secret, receiver_shared_secret);
        assert_eq!(sender_shared_secret, repeated_shared_secret);
        assert_eq!(enc, repeated_enc);
    }
}
