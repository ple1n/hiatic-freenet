use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot};

use crate::{
    DerivationContext, Error, GroupCiphertext, GroupId, GroupKeyHandle, HpkeRecipientKeypair,
    HpkeSuite, KeyId, RecipientKeyHandle, Secret256, SessionKey, VolatileSecret, Wallet,
};

#[derive(Clone)]
pub struct WalletHandle {
    commands: mpsc::Sender<Command>,
}

enum Command {
    DeriveL1 {
        context: DerivationContext,
        volatile: Option<VolatileSecret>,
        reply: oneshot::Sender<Result<KeyId, Error>>,
    },
    DeriveSenderSessionKey {
        l1: KeyId,
        recipient_public_key: Vec<u8>,
        suite: HpkeSuite,
        volatile: Option<VolatileSecret>,
        reply: oneshot::Sender<Result<SessionKey, Error>>,
    },
    ImportL1 {
        key: Secret256,
        reply: oneshot::Sender<Result<KeyId, Error>>,
    },
    DeriveRecipientKey {
        l1: KeyId,
        context: DerivationContext,
        suite: HpkeSuite,
        volatile: Option<VolatileSecret>,
        reply: oneshot::Sender<Result<(RecipientKeyHandle, Vec<u8>), Error>>,
    },
    DecapsulateSession {
        recipient: RecipientKeyHandle,
        encapsulation: Vec<u8>,
        reply: oneshot::Sender<Result<Secret256, Error>>,
    },
    CreateGroup {
        group: GroupId,
        reply: oneshot::Sender<Result<GroupKeyHandle, Error>>,
    },
    GetGroupKey {
        group: GroupId,
        reply: oneshot::Sender<Result<Option<GroupKeyHandle>, Error>>,
    },
    ImportGroup {
        group: GroupId,
        key: Secret256,
        reply: oneshot::Sender<Result<GroupKeyHandle, Error>>,
    },
    EncryptGroup {
        group: GroupKeyHandle,
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
        reply: oneshot::Sender<Result<GroupCiphertext, Error>>,
    },
    DecryptGroup {
        group: GroupKeyHandle,
        ciphertext: GroupCiphertext,
        associated_data: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>, Error>>,
    },
    Lock {
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

pub fn spawn(wallet: Wallet) -> WalletHandle {
    let (commands, mut receiver) = mpsc::channel(32);
    tokio::spawn(async move {
        let mut wallet = Some(wallet);
        let mut recipient_keys = HashMap::new();
        while let Some(command) = receiver.recv().await {
            match command {
                Command::DeriveL1 {
                    context,
                    volatile,
                    reply,
                } => {
                    let result = wallet
                        .as_mut()
                        .ok_or(Error::ActorUnavailable)
                        .and_then(|wallet| wallet.derive_l1(context, volatile));
                    let _ = reply.send(result);
                }
                Command::ImportL1 { key, reply } => {
                    let result = wallet
                        .as_mut()
                        .ok_or(Error::ActorUnavailable)
                        .and_then(|wallet| wallet.import_l1(key));
                    let _ = reply.send(result);
                }
                Command::DeriveSenderSessionKey {
                    l1,
                    recipient_public_key,
                    suite,
                    volatile,
                    reply,
                } => {
                    let result =
                        wallet
                            .as_ref()
                            .ok_or(Error::ActorUnavailable)
                            .and_then(|wallet| {
                                wallet.derive_sender_session_key(
                                    l1,
                                    &recipient_public_key,
                                    suite,
                                    volatile.as_ref(),
                                )
                            });
                    let _ = reply.send(result);
                }
                Command::DeriveRecipientKey {
                    l1,
                    context,
                    suite,
                    volatile,
                    reply,
                } => {
                    let result =
                        wallet
                            .as_ref()
                            .ok_or(Error::ActorUnavailable)
                            .and_then(|wallet| {
                                let keypair = wallet.derive_recipient_keypair(
                                    l1,
                                    context,
                                    suite,
                                    volatile.as_ref(),
                                )?;
                                let handle = fresh_recipient_handle(&recipient_keys)?;
                                let public_key = keypair.public_key_bytes().to_vec();
                                recipient_keys.insert(handle, keypair);
                                Ok((handle, public_key))
                            });
                    let _ = reply.send(result);
                }
                Command::DecapsulateSession {
                    recipient,
                    encapsulation,
                    reply,
                } => {
                    let result = if wallet.is_none() {
                        Err(Error::ActorUnavailable)
                    } else {
                        recipient_keys
                            .get(&recipient)
                            .ok_or(Error::KeyNotFound)
                            .and_then(|keypair| keypair.decapsulate(&encapsulation))
                    };
                    let _ = reply.send(result);
                }
                Command::CreateGroup { group, reply } => {
                    let result = wallet
                        .as_mut()
                        .ok_or(Error::ActorUnavailable)
                        .and_then(|wallet| wallet.create_group_key(group));
                    let _ = reply.send(result);
                }
                Command::GetGroupKey { group, reply } => {
                    let result = wallet
                        .as_ref()
                        .ok_or(Error::ActorUnavailable)
                        .map(|wallet| wallet.group_key(group));
                    let _ = reply.send(result);
                }
                Command::ImportGroup { group, key, reply } => {
                    let result = wallet
                        .as_mut()
                        .ok_or(Error::ActorUnavailable)
                        .and_then(|wallet| wallet.import_group_key(group, key));
                    let _ = reply.send(result);
                }
                Command::EncryptGroup {
                    group,
                    plaintext,
                    associated_data,
                    reply,
                } => {
                    let result =
                        wallet
                            .as_ref()
                            .ok_or(Error::ActorUnavailable)
                            .and_then(|wallet| {
                                wallet.encrypt_group(group, &plaintext, &associated_data)
                            });
                    let _ = reply.send(result);
                }
                Command::DecryptGroup {
                    group,
                    ciphertext,
                    associated_data,
                    reply,
                } => {
                    let result =
                        wallet
                            .as_ref()
                            .ok_or(Error::ActorUnavailable)
                            .and_then(|wallet| {
                                wallet.decrypt_group(group, &ciphertext, &associated_data)
                            });
                    let _ = reply.send(result);
                }
                Command::Lock { reply } => {
                    drop(wallet.take());
                    recipient_keys.clear();
                    let _ = reply.send(Ok(()));
                    break;
                }
            }
        }
    });
    WalletHandle { commands }
}

impl WalletHandle {
    pub async fn derive_l1(
        &self,
        context: DerivationContext,
        volatile: Option<VolatileSecret>,
    ) -> Result<KeyId, Error> {
        self.request(|reply| Command::DeriveL1 {
            context,
            volatile,
            reply,
        })
        .await
    }

    pub async fn import_l1(&self, key: Secret256) -> Result<KeyId, Error> {
        self.request(|reply| Command::ImportL1 { key, reply }).await
    }

    pub async fn derive_sender_session_key(
        &self,
        l1: KeyId,
        recipient_public_key: Vec<u8>,
        suite: HpkeSuite,
        volatile: Option<VolatileSecret>,
    ) -> Result<SessionKey, Error> {
        self.request(|reply| Command::DeriveSenderSessionKey {
            l1,
            recipient_public_key,
            suite,
            volatile,
            reply,
        })
        .await
    }

    pub async fn derive_recipient_key(
        &self,
        l1: KeyId,
        context: DerivationContext,
        suite: HpkeSuite,
        volatile: Option<VolatileSecret>,
    ) -> Result<(RecipientKeyHandle, Vec<u8>), Error> {
        self.request(|reply| Command::DeriveRecipientKey {
            l1,
            context,
            suite,
            volatile,
            reply,
        })
        .await
    }

    pub async fn decapsulate_session(
        &self,
        recipient: RecipientKeyHandle,
        encapsulation: Vec<u8>,
    ) -> Result<Secret256, Error> {
        self.request(|reply| Command::DecapsulateSession {
            recipient,
            encapsulation,
            reply,
        })
        .await
    }

    pub async fn create_group_key(&self, group: GroupId) -> Result<GroupKeyHandle, Error> {
        self.request(|reply| Command::CreateGroup { group, reply })
            .await
    }

    pub async fn get_group_key(&self, group: GroupId) -> Result<Option<GroupKeyHandle>, Error> {
        self.request(|reply| Command::GetGroupKey { group, reply })
            .await
    }

    pub async fn import_group_key(
        &self,
        group: GroupId,
        key: Secret256,
    ) -> Result<GroupKeyHandle, Error> {
        self.request(|reply| Command::ImportGroup { group, key, reply })
            .await
    }

    pub async fn encrypt_group(
        &self,
        group: GroupKeyHandle,
        plaintext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<GroupCiphertext, Error> {
        self.request(|reply| Command::EncryptGroup {
            group,
            plaintext,
            associated_data,
            reply,
        })
        .await
    }

    pub async fn decrypt_group(
        &self,
        group: GroupKeyHandle,
        ciphertext: GroupCiphertext,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        self.request(|reply| Command::DecryptGroup {
            group,
            ciphertext,
            associated_data,
            reply,
        })
        .await
    }

    pub async fn lock(&self) -> Result<(), Error> {
        self.request(|reply| Command::Lock { reply }).await
    }

    async fn request<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> Command,
    ) -> Result<T, Error> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(build(reply))
            .await
            .map_err(|_| Error::ActorUnavailable)?;
        result.await.map_err(|_| Error::ActorUnavailable)?
    }
}

fn fresh_recipient_handle(
    keys: &HashMap<RecipientKeyHandle, HpkeRecipientKeypair>,
) -> Result<RecipientKeyHandle, Error> {
    loop {
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(Error::from)?;
        let handle = RecipientKeyHandle(id);
        if !keys.contains_key(&handle) {
            return Ok(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HpkeKeyEncapsulation, HpkeSuite, KeyEncapsulation};

    #[tokio::test]
    async fn actor_serializes_state_changes_and_locks() {
        let wallet = Wallet::from_master(Secret256::from_bytes([11; 32]));
        let actor = spawn(wallet);
        let group_id = GroupId([3; 32]);
        let group = actor.create_group_key(group_id).await.unwrap();
        assert_eq!(actor.get_group_key(group_id).await.unwrap(), Some(group));
        let sealed = actor
            .encrypt_group(group, b"hello".to_vec(), b"group".to_vec())
            .await
            .unwrap();
        assert_eq!(
            actor
                .decrypt_group(group, sealed, b"group".to_vec())
                .await
                .unwrap(),
            b"hello"
        );
        actor.lock().await.unwrap();
        assert_eq!(
            actor.create_group_key(GroupId([4; 32])).await,
            Err(Error::ActorUnavailable)
        );
    }

    #[tokio::test]
    async fn actor_kem_shared_secret_matches_recipient_decapsulation() {
        let suite = HpkeSuite::XWing;
        let sender = spawn(Wallet::from_master(Secret256::from_bytes([1; 32])));
        let receiver = spawn(Wallet::from_master(Secret256::from_bytes([2; 32])));
        let recipient_l1 = receiver
            .derive_l1(DerivationContext::new(b"scope/receiver/messaging"), None)
            .await
            .unwrap();
        let (recipient, recipient_public_key) = receiver
            .derive_recipient_key(
                recipient_l1,
                DerivationContext::new(b"peer/alice/dm-1"),
                suite,
                None,
            )
            .await
            .unwrap();

        let branch = sender
            .derive_l1(DerivationContext::new(b"shared-room-branch"), None)
            .await
            .unwrap();
        let session_key = sender
            .derive_sender_session_key(branch, recipient_public_key.clone(), suite, None)
            .await
            .unwrap();
        let (encapsulation, sender_shared_secret) = HpkeKeyEncapsulation::new(suite)
            .encapsulate(&recipient_public_key, &session_key)
            .unwrap();
        let receiver_shared_secret = receiver
            .decapsulate_session(recipient, encapsulation)
            .await
            .unwrap();
        assert_eq!(sender_shared_secret, receiver_shared_secret);
    }
}
