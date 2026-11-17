mod derivation;
mod error;
mod key;
pub mod signing;
mod transport;
mod wallet;

#[cfg(feature = "actor")]
pub mod actor;

pub use derivation::{DerivationContext, VolatileSecret};
pub use error::Error;
pub use key::{
    GroupCiphertext, GroupId, GroupKeyHandle, KeyId, RecipientKeyHandle, Secret256, SessionKey,
};
pub use transport::{HpkeKeyEncapsulation, HpkeRecipientKeypair, HpkeSuite, KeyEncapsulation};
pub use wallet::Wallet;

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet() -> Wallet {
        Wallet::from_master(Secret256::from_bytes([7; 32]))
    }

    #[test]
    fn deterministic_l1_derivation_is_repeatable() {
        let mut wallet = wallet();
        let first = wallet
            .derive_l1(DerivationContext::new(b"room/group-a"), None)
            .unwrap();
        let second = wallet
            .derive_l1(DerivationContext::new(b"room/group-a"), None)
            .unwrap();

        assert_eq!(
            wallet
                .derive_local(first, DerivationContext::new(b"message-key"), None)
                .unwrap(),
            wallet
                .derive_local(second, DerivationContext::new(b"message-key"), None)
                .unwrap(),
        );
    }

    #[test]
    fn volatile_input_changes_the_derived_branch() {
        let mut wallet = wallet();
        let first = wallet
            .derive_l1(
                DerivationContext::new(b"room/group-a"),
                Some(VolatileSecret::from_bytes([1; 32])),
            )
            .unwrap();
        let second = wallet
            .derive_l1(
                DerivationContext::new(b"room/group-a"),
                Some(VolatileSecret::from_bytes([2; 32])),
            )
            .unwrap();

        assert_ne!(
            wallet
                .derive_local(first, DerivationContext::new(b"message-key"), None)
                .unwrap(),
            wallet
                .derive_local(second, DerivationContext::new(b"message-key"), None)
                .unwrap(),
        );
    }

    #[test]
    fn group_key_encrypts_and_authenticates_messages() {
        let mut wallet = wallet();
        let group = GroupId([9; 32]);
        let group_key = wallet.create_group_key(group).unwrap();
        let sealed = wallet
            .encrypt_group(group_key, b"hello", b"room-a")
            .unwrap();

        assert_eq!(
            wallet.decrypt_group(group_key, &sealed, b"room-a").unwrap(),
            b"hello"
        );
        assert!(wallet.decrypt_group(group_key, &sealed, b"room-b").is_err());
    }

    #[test]
    fn kem_session_secret_is_shared_without_transferring_l1() {
        let suite = HpkeSuite::XWing;
        let encapsulation = HpkeKeyEncapsulation::new(suite);
        let mut recipient_wallet = Wallet::from_master(Secret256::from_bytes([8; 32]));
        let recipient_l1 = recipient_wallet
            .derive_l1(DerivationContext::new(b"scope/recipient/messaging"), None)
            .unwrap();
        let recipient = recipient_wallet
            .derive_recipient_keypair(
                recipient_l1,
                DerivationContext::new(b"peer/sender/shared-room"),
                suite,
                None,
            )
            .unwrap();
        let mut sender = wallet();
        let sender_branch = sender
            .derive_l1(DerivationContext::new(b"scope/shared-room"), None)
            .unwrap();
        let session_key = sender
            .derive_sender_session_key(sender_branch, recipient.public_key_bytes(), suite, None)
            .unwrap();
        let (enc, sender_shared_secret) = encapsulation
            .encapsulate(recipient.public_key_bytes(), &session_key)
            .unwrap();
        let recipient_shared_secret = recipient.decapsulate(&enc).unwrap();
        assert_eq!(sender_shared_secret, recipient_shared_secret);
    }

    #[test]
    fn session_keys_are_reproducible_for_scope_peer_and_suite() {
        let mut wallet = wallet();
        let scope_l1 = wallet
            .derive_l1(DerivationContext::new(b"scope/messaging"), None)
            .unwrap();
        let rotated_l1 = wallet
            .derive_l1(DerivationContext::new(b"scope/messaging/rotation-2"), None)
            .unwrap();

        let recipient = [3; 32];
        let other_recipient = [4; 32];
        let first = wallet
            .derive_sender_session_key(scope_l1, &recipient, HpkeSuite::X25519, None)
            .unwrap();
        let mut restored_wallet = Wallet::from_master(Secret256::from_bytes([7; 32]));
        let restored_l1 = restored_wallet
            .derive_l1(DerivationContext::new(b"scope/messaging"), None)
            .unwrap();
        let restored = restored_wallet
            .derive_sender_session_key(restored_l1, &recipient, HpkeSuite::X25519, None)
            .unwrap();
        let other_l1 = wallet
            .derive_sender_session_key(rotated_l1, &recipient, HpkeSuite::X25519, None)
            .unwrap();
        let other_recipient = wallet
            .derive_sender_session_key(scope_l1, &other_recipient, HpkeSuite::X25519, None)
            .unwrap();
        let other_suite = wallet
            .derive_sender_session_key(scope_l1, &recipient, HpkeSuite::XWing, None)
            .unwrap();

        assert_eq!(first, restored);
        assert_ne!(first, other_l1);
        assert_ne!(first, other_recipient);
        assert_ne!(first, other_suite);

        let volatile = VolatileSecret::from_bytes([8; 32]);
        let with_volatile = wallet
            .derive_sender_session_key(scope_l1, &recipient, HpkeSuite::X25519, Some(&volatile))
            .unwrap();
        assert_ne!(first, with_volatile);
    }

    #[test]
    fn recipient_keypair_is_reproducible_from_recipient_wallet() {
        let suite = HpkeSuite::XWing;
        let recipient_master = Secret256::from_bytes([30; 32]);
        let peer_context = DerivationContext::new(b"peer/alice/dm-1");

        let (recipient_public_key, encapsulation, expected_shared_secret) = {
            let mut wallet = Wallet::from_master(recipient_master.duplicate());
            let l1 = wallet
                .derive_l1(DerivationContext::new(b"scope/recipient/messaging"), None)
                .unwrap();
            let recipient_keypair = wallet
                .derive_recipient_keypair(l1, peer_context, suite, None)
                .unwrap();
            let recipient_public_key = recipient_keypair.public_key_bytes().to_vec();

            let sender_session_key = SessionKey::from_secret(Secret256::from_bytes([31; 32]));
            let (encapsulation, shared_secret) = HpkeKeyEncapsulation::new(suite)
                .encapsulate(&recipient_public_key, &sender_session_key)
                .unwrap();
            (recipient_public_key, encapsulation, shared_secret)
        };

        let mut restored_wallet = Wallet::from_master(recipient_master);
        let restored_l1 = restored_wallet
            .derive_l1(DerivationContext::new(b"scope/recipient/messaging"), None)
            .unwrap();
        let restored_keypair = restored_wallet
            .derive_recipient_keypair(
                restored_l1,
                DerivationContext::new(b"peer/alice/dm-1"),
                suite,
                None,
            )
            .unwrap();
        assert_eq!(recipient_public_key, restored_keypair.public_key_bytes());
        assert_eq!(
            expected_shared_secret,
            restored_keypair.decapsulate(&encapsulation).unwrap()
        );
    }

    #[test]
    fn dm_ciphertext_can_be_read_after_wallet_restart() {
        let suite = HpkeSuite::XWing;
        let kem = HpkeKeyEncapsulation::new(suite);
        let bob_master = [34; 32];
        let bob_public_key = {
            let mut bob = Wallet::from_master(Secret256::from_bytes(bob_master));
            let bob_l1 = bob
                .derive_l1(DerivationContext::new(b"scope/bob/messaging"), None)
                .unwrap();
            bob.derive_recipient_keypair(
                bob_l1,
                DerivationContext::new(b"peer/alice/dm"),
                suite,
                None,
            )
            .unwrap()
            .public_key_bytes()
            .to_vec()
        };
        let master = [31; 32];
        let l1_volatile = [32; 32];
        let dm = GroupId([33; 32]);
        let plaintext = b"message after restart";

        let (encapsulation, ciphertext) = {
            let mut alice = Wallet::from_master(Secret256::from_bytes(master));
            let alice_l1 = alice
                .derive_l1(
                    DerivationContext::new(b"scope/alice/messaging"),
                    Some(VolatileSecret::from_bytes(l1_volatile)),
                )
                .unwrap();
            let session_key = alice
                .derive_sender_session_key(alice_l1, &bob_public_key, suite, None)
                .unwrap();
            // The sender transmits the encapsulation to Bob; the shared secret stays local.
            let (encapsulation, alice_shared_secret) =
                kem.encapsulate(&bob_public_key, &session_key).unwrap();

            let alice_group = alice
                .import_group_key(dm, Secret256::from_bytes(*alice_shared_secret.expose()))
                .unwrap();
            let ciphertext = alice
                .encrypt_group(alice_group, plaintext, b"dm/alice-bob")
                .unwrap();
            // Model the wire payload: send the encapsulation and ciphertext, never the shared secret.
            (encapsulation, ciphertext)
        };

        let mut alice = Wallet::from_master(Secret256::from_bytes(master));
        let alice_l1 = alice
            .derive_l1(
                DerivationContext::new(b"scope/alice/messaging"),
                Some(VolatileSecret::from_bytes(l1_volatile)),
            )
            .unwrap();
        let session_key = alice
            .derive_sender_session_key(alice_l1, &bob_public_key, suite, None)
            .unwrap();
        let (recreated_encapsulation, alice_shared_secret) =
            kem.encapsulate(&bob_public_key, &session_key).unwrap();
        assert_eq!(encapsulation, recreated_encapsulation);

        let alice_group = alice.import_group_key(dm, alice_shared_secret).unwrap();
        assert_eq!(
            alice
                .decrypt_group(alice_group, &ciphertext, b"dm/alice-bob")
                .unwrap(),
            plaintext
        );

        let mut bob = Wallet::from_master(Secret256::from_bytes([34; 32]));
        let bob_l1 = bob
            .derive_l1(DerivationContext::new(b"scope/bob/messaging"), None)
            .unwrap();
        // Bob recreates his recipient keypair from wallet material, then decapsulates.
        let bob_recipient = bob
            .derive_recipient_keypair(
                bob_l1,
                DerivationContext::new(b"peer/alice/dm"),
                suite,
                None,
            )
            .unwrap();
        assert_eq!(bob_public_key, bob_recipient.public_key_bytes());
        let bob_shared_secret = bob_recipient.decapsulate(&encapsulation).unwrap();
        let bob_group = bob.import_group_key(dm, bob_shared_secret).unwrap();
        assert_eq!(
            bob.decrypt_group(bob_group, &ciphertext, b"dm/alice-bob")
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn public_key_signing_is_separate_from_group_encryption() {
        let seed = Secret256::from_bytes([6; 32]);
        let signer = signing::Ed25519Signer::from_seed(&seed);
        let message = b"authorization statement";
        let signature = signer.sign(message);

        assert!(signing::Ed25519Signer::verify(
            &signer.public_key(),
            message,
            &signature,
        ));
        assert!(!signing::Ed25519Signer::verify(
            &signer.public_key(),
            b"different statement",
            &signature,
        ));
    }
}
