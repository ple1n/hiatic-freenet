use std::collections::HashMap;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{
    DerivationContext, Error, GroupCiphertext, GroupId, GroupKeyHandle, HpkeRecipientKeypair,
    HpkeSuite, KeyId, Secret256, SessionKey, VolatileSecret, derivation::derive,
};

enum L1Material {
    Derived {
        context: DerivationContext,
        volatile: Option<VolatileSecret>,
    },
    Imported(Secret256),
}

struct GroupKeyRecord {
    group: GroupId,
    key: Secret256,
}

pub struct Wallet {
    master: Secret256,
    l1: HashMap<KeyId, L1Material>,
    groups: HashMap<GroupKeyHandle, GroupKeyRecord>,
    group_handles: HashMap<GroupId, GroupKeyHandle>,
}

impl Wallet {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_master(Secret256::generate()?))
    }

    pub fn from_master(master: Secret256) -> Self {
        Self {
            master,
            l1: HashMap::new(),
            groups: HashMap::new(),
            group_handles: HashMap::new(),
        }
    }

    pub fn derive_l1(
        &mut self,
        context: DerivationContext,
        volatile: Option<VolatileSecret>,
    ) -> Result<KeyId, Error> {
        let id = self.new_key_id()?;
        self.l1
            .insert(id, L1Material::Derived { context, volatile });
        Ok(id)
    }

    pub fn import_l1(&mut self, key: Secret256) -> Result<KeyId, Error> {
        let id = self.new_key_id()?;
        self.l1.insert(id, L1Material::Imported(key));
        Ok(id)
    }

    pub fn derive_local(
        &self,
        parent: KeyId,
        context: DerivationContext,
        volatile: Option<&VolatileSecret>,
    ) -> Result<Secret256, Error> {
        let branch = self.l1_material(parent)?;
        Ok(derive(&branch, &context, volatile))
    }

    /// Derives this sender wallet's KEM seed from its L1 key and recipient.
    ///
    /// The suite and recipient public key are domain-separated into the
    /// context. The same inputs reproduce the same `SessionKey`, and therefore
    /// the same KEM encapsulation and shared secret.
    ///
    /// For optional forward secrecy against later L1 compromise, provide a
    /// fresh volatile input and erase it after deriving the session key. This
    /// alone does not protect recorded encapsulations from later compromise of
    /// a static recipient private key; that requires ephemeral or ratcheted
    /// recipient keys.
    pub fn derive_sender_session_key(
        &self,
        l1: KeyId,
        recipient_public_key: &[u8],
        suite: HpkeSuite,
        volatile: Option<&VolatileSecret>,
    ) -> Result<SessionKey, Error> {
        let l1_key = self.l1_material(l1)?;
        let mut context = b"hiatic-crypto/hpke-session-key/v1".to_vec();
        context.push(suite.id());
        context.extend_from_slice(&(recipient_public_key.len() as u64).to_be_bytes());
        context.extend_from_slice(recipient_public_key);
        let session_key = derive(&l1_key, &DerivationContext::new(context), volatile);
        Ok(SessionKey::from_secret(session_key))
    }

    /// Derives the recipient wallet's seed for its deterministic KEM keypair.
    ///
    /// Use a recipient-private L1 and a stable peer/session context. The same
    /// inputs reproduce the same keypair through
    /// [`HpkeRecipientKeypair::from_session_key`]. If `volatile` is supplied,
    /// the same value must be available to recreate the keypair after restart.
    pub fn derive_recipient_session_key(
        &self,
        l1: KeyId,
        context: DerivationContext,
        suite: HpkeSuite,
        volatile: Option<&VolatileSecret>,
    ) -> Result<SessionKey, Error> {
        let l1_key = self.l1_material(l1)?;
        let mut derivation_context = b"hiatic-crypto/recipient-kem-key/v1".to_vec();
        derivation_context.push(suite.id());
        derivation_context.extend_from_slice(&(context.as_bytes().len() as u64).to_be_bytes());
        derivation_context.extend_from_slice(context.as_bytes());
        let session_key = derive(
            &l1_key,
            &DerivationContext::new(derivation_context),
            volatile,
        );
        Ok(SessionKey::from_secret(session_key))
    }

    /// Recreates a recipient keypair using only recipient-wallet derivation inputs.
    pub fn derive_recipient_keypair(
        &self,
        l1: KeyId,
        context: DerivationContext,
        suite: HpkeSuite,
        volatile: Option<&VolatileSecret>,
    ) -> Result<HpkeRecipientKeypair, Error> {
        let session_key = self.derive_recipient_session_key(l1, context, suite, volatile)?;
        Ok(HpkeRecipientKeypair::from_session_key(suite, &session_key))
    }

    pub fn group_key(&self, group: GroupId) -> Option<GroupKeyHandle> {
        self.group_handles.get(&group).copied()
    }

    pub fn create_group_key(&mut self, group: GroupId) -> Result<GroupKeyHandle, Error> {
        if self.group_handles.contains_key(&group) {
            return Err(Error::KeyAlreadyExists);
        }

        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(Error::from)?;
        let handle = self.new_group_handle()?;
        self.groups.insert(
            handle,
            GroupKeyRecord {
                group,
                key: Secret256::from_bytes(*bytes),
            },
        );
        self.group_handles.insert(group, handle);
        Ok(handle)
    }

    pub fn import_group_key(
        &mut self,
        group: GroupId,
        key: Secret256,
    ) -> Result<GroupKeyHandle, Error> {
        if self.group_handles.contains_key(&group) {
            return Err(Error::KeyAlreadyExists);
        }
        let handle = self.new_group_handle()?;
        self.groups.insert(handle, GroupKeyRecord { group, key });
        self.group_handles.insert(group, handle);
        Ok(handle)
    }

    pub fn encrypt_group(
        &self,
        handle: GroupKeyHandle,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<GroupCiphertext, Error> {
        let record = self.groups.get(&handle).ok_or(Error::KeyNotFound)?;
        let cipher = ChaCha20Poly1305::new_from_slice(record.key.expose())
            .map_err(|_| Error::AuthenticationFailed)?;
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(Error::from)?;
        let nonce = Nonce::from(nonce);
        let aad = group_message_aad(record.group, associated_data);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(GroupCiphertext {
            nonce: nonce.into(),
            ciphertext,
        })
    }

    pub fn decrypt_group(
        &self,
        handle: GroupKeyHandle,
        ciphertext: &GroupCiphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let record = self.groups.get(&handle).ok_or(Error::KeyNotFound)?;
        let cipher = ChaCha20Poly1305::new_from_slice(record.key.expose())
            .map_err(|_| Error::AuthenticationFailed)?;
        let nonce = Nonce::from(ciphertext.nonce);
        let aad = group_message_aad(record.group, associated_data);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::AuthenticationFailed)
    }

    pub fn forget_group_key(&mut self, handle: GroupKeyHandle) -> Result<(), Error> {
        let record = self.groups.remove(&handle).ok_or(Error::KeyNotFound)?;
        self.group_handles.remove(&record.group);
        drop(record);
        Ok(())
    }

    pub fn forget_l1(&mut self, key: KeyId) -> Result<(), Error> {
        self.l1.remove(&key).map(drop).ok_or(Error::KeyNotFound)
    }

    fn l1_material(&self, id: KeyId) -> Result<Secret256, Error> {
        match self.l1.get(&id).ok_or(Error::KeyNotFound)? {
            L1Material::Derived { context, volatile } => {
                Ok(derive(&self.master, context, volatile.as_ref()))
            }
            L1Material::Imported(key) => Ok(key.duplicate()),
        }
    }

    fn new_key_id(&self) -> Result<KeyId, Error> {
        loop {
            let mut id = [0; 16];
            getrandom::fill(&mut id).map_err(Error::from)?;
            let id = KeyId(id);
            if !self.l1.contains_key(&id) {
                return Ok(id);
            }
        }
    }

    fn new_group_handle(&self) -> Result<GroupKeyHandle, Error> {
        loop {
            let mut id = [0; 16];
            getrandom::fill(&mut id).map_err(Error::from)?;
            let handle = GroupKeyHandle(id);
            if !self.groups.contains_key(&handle) {
                return Ok(handle);
            }
        }
    }
}

fn group_message_aad(group: GroupId, associated_data: &[u8]) -> Vec<u8> {
    let mut aad = b"hiatic-crypto/group-message/v1".to_vec();
    aad.extend_from_slice(&group.0);
    aad.extend_from_slice(&(associated_data.len() as u64).to_be_bytes());
    aad.extend_from_slice(associated_data);
    aad
}
