# Task 1: key-derivation library

This library should make wallet keys easy to understand, restore, synchronize,
and share.

## Key model

- **Master key:** stays in one wallet and is never shared.
- **L1 key:** derived for a scope or rotation generation. A user can sync an
  L1 key across their own devices without sharing the master. An L1 key grants
  access to its branch and descendants.
- **Recipient keypair:** derived from a `SessionKey` created by the recipient's
  wallet. The recipient can recreate the same keypair from the same L1,
  context, suite, and optional volatile input.
- **Sender `SessionKey`:** derived by the sender's wallet from its L1, the
  recipient's public key, the suite, and optional volatile input. It seeds the
  sender's KEM randomness, so the sender can reproduce the encapsulation.
- **KEM exchange:** the sender sends the encapsulation, not the shared secret.
  The sender gets the shared secret from encapsulation; the recipient gets the
  same secret from decapsulation. The sender should retain its `SessionKey`
  and shared secret. The receiver should retain the shared secret. If the
  receiver loses it, the sender can resend the encapsulation, provided the
  receiver can recover its private key.
- **Group key:** a symmetric key that multiple people can hold. It is not tied
  to a particular purpose and can be shared between users.
- **Key distribution:** the wallet uses KEM to establish a shared secret for
  one-to-one distribution when no secure channel exists. If a secure channel
  already exists, send the key directly through it.

## Goals

- Keep wallets understandable and manageable with low-level tools such as a
  CLI. Users should be able to inspect wallet state and how keys are derived,
  without exposing secret values.
- Make syncing keys across one user's devices simple and reliable.
- Make sharing access with other people efficient, including sharing group
  keys.
- Make derivation paths clear so users can understand which inputs produce
  each key and avoid unnecessary key-management work.
- Clearly distinguish deterministic derivation from operations that use fresh
  randomness.
- Keep the master key private; deriving a child key must not reveal its
  parent.

## Rotation and scope

L1 contexts identify scopes or rotation generations, not individual
recipients. Rotating an L1 changes future access, but cannot revoke old copies
or keys already derived from them; protocols must handle key versions or
revocation. Master-key rotation is out of scope; create a new wallet instead.

## Further goals

- Support post-hoc proofs of key ownership without revealing upstream keys.
  Poseidon2 may make derivation more efficient in zero-knowledge circuits;
  the current HMAC-SHA256 implementation does not provide this.
- Keep key operations simple and dependencies minimal. Ratchet encryption is
  out of scope for now because of its synchronization complexity.

## Implementation status

Recipient keypairs can be recreated from the recipient wallet's `SessionKey`,
and sender encapsulation is deterministic from the sender's `SessionKey`.
Wallet serialization and persistent storage of KEM session records are not
implemented yet.