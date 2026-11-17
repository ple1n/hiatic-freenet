# Membership and authorship

Room state contains a collection of public keys of different kinds. Member
commitments count as public keys:

- Member commitments in a Poseidon Merkle tree for ZK membership proofs.
- Authorized FN-DSA public keys for daily post signatures.
- Authorized pre-quantum public keys, which can be turned off after migration.

The tree contains commitments only; it does not pair them with signing keys.

The tree supports on-demand anonymity, such as adding an account by proving
membership anonymously. A room-membership proof can also be composed into a
larger ZK proof and used as a CAPTCHA alternative on websites that accept it.

ZK and post-quantum support may be unused or unavailable. The system should
still function with pre-quantum keys, which are cheaper and easier to use.
