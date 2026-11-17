# Key hierarchy and derivation

The hierarchy separates device-root custody, shareable L1 branches, and
reproducible session private keys. Its purpose is to make access easy to share
without exposing upstream keys. Deterministic derivation reduces both secret
storage and the bookkeeping needed to regenerate keys.

## Design goals

- Keep wallets manageable with low-level tools such as a CLI. Key state,
  derivation contexts, and sharing operations should be inspectable rather
  than hidden behind opaque abstractions.
- Make cross-device key synchronization simple enough to avoid mistakes.
- Support efficient sharing of access among users.
- Make derivation mechanisms clear so users can understand and reduce key
  management overhead.
- Separate deterministic derivation from non-deterministic key generation
  explicitly.

## Master wallet key

The persistent master wallet key stays on one device and is never shared.
Lower-level keys are derived from it, but possession of a derived key must not
reveal the master.

## L1 keys

An L1 key is derived from the master using a deterministic branch context and
an additional volatile entropy input:

```text
L1 = derive(master, L1 context, optional volatile entropy)
```

Here, `derive` means the library's domain-separated HMAC-SHA256 child-key
derivation, not a password KDF.

L1 keys are the cross-device synchronization boundary for wallets belonging
to the same user. A user can securely synchronize an L1 key across their
devices without exporting the master. Compromise of an L1 key exposes that L1
branch and its descendants, but must not expose the master or unrelated L1
branches. L1 keys are not the general person-to-person sharing mechanism;
group keys serve that purpose.

An L1 context identifies a scope or key generation, not an individual
recipient. Recipient-specific derivation happens at the session-key layer.

The volatile input is needed to reproduce the L1 key from the master and
context. Keeping it separate allows that ability to be discarded; it does not
revoke copies of an L1 key that have already been shared.

L1 rotation is in scope. A user can derive and distribute a replacement L1
branch to change future access. Rotation cannot revoke old L1 copies or keys
already derived from them; protocols using those keys must handle versioning
or revocation. Master-key rotation is out of scope: create a new wallet
instead.

## Session keys and recipient keypairs

Each side derives a `SessionKey` from its wallet for its KEM role. The
sender's `SessionKey` seeds encapsulation; the recipient's `SessionKey`
derives its KEM keypair.

The recipient wallet derives a recipient-side `SessionKey` from a
recipient-private L1 key, a stable peer/session context, and the KEM suite,
with an optional volatile input:

```text
recipient SessionKey = derive(recipient L1, context(peer/session, suite), optional volatile input)
recipient keypair = KEM.DeriveKeyPair(recipient SessionKey)
```

The recipient can recreate the same keypair after restart from the same
wallet material and derivation inputs. The L1 used here must not be shared with
the sender, or the sender could derive the recipient private key too. If a
volatile input is used, it must be available again to recreate the keypair;
erasing it prevents that recovery.

Separately, the sender derives its KEM-randomness `SessionKey` from its own L1,
the recipient public key, suite, and optional volatile input:

```text
sender SessionKey = derive(sender L1, context(recipient public key, suite), optional volatile input)
```

That sender `SessionKey` seeds encapsulation. For fixed inputs, the sender can
reproduce the same encapsulation, including any KEM ephemeral secret material,
and shared secret. The encapsulation travels with the message; the shared
secret does not. The recipient decapsulates using its recipient private key.

For recoverable KEM sessions, the sender wallet should retain the sender
`SessionKey` and shared secret. The receiver wallet should retain the shared
secret; its recipient keypair can be recreated from its own wallet material.
If the receiver loses its cached shared secret, the sender can resend the
encapsulation and the receiver can decapsulate it again. The current wallet
implementation does not yet serialize these session records across process
restarts.

## ZK-friendly derivation and ownership proofs

Poseidon2 is a candidate hash for making derivation and key-ownership proofs
efficient inside a zero-knowledge circuit. The derivation path should support
post-hoc proofs that a key is owned or correctly derived without revealing
the master or upstream keys. Anonymity also depends on which public inputs the
proof reveals.

This is a design goal, not a property of the current HMAC-SHA256
implementation. Any Poseidon2 design needs fixed encodings, domain separation,
and cryptographic review before replacing the current derivation.

## Other key decisions

For DMs, a shared session secret can be established using a post-quantum or
pre-quantum key encapsulation scheme. Message encryption is a separate use of
that shared secret.

## Key distribution

The wallet supports two ways to distribute key material:

- For one-to-one distribution without a prior secure channel, use a KEM to
  establish a shared secret.
- If a secure channel already exists, send the key directly through that
  channel.

Group keys are symmetric keys intended to be held by multiple people. They
are purpose-agnostic: the key model does not restrict a group key to a
particular use. A group key can be generated by one wallet and shared with
other users; it is separate from L1 derivation and synchronization.

Ratchet encryption is avoided due to synchronization complexity.

The design should support easy creation of unlinkable invite codes and
unlinkable identities.
