# Task 1

The first task to finish is key-derivation lib. This forms the most basic functionality of the chat platform. 

Key design principles

- Self-custodial as layer-1; Custodianship is a layer-2 thing to be built by users.
- Minimalism. No ratchet encryption or complex distributed algos here. 
- Keys and basic work must be operable with minimal other dependency
- Wallet-style UX and seed-to-key derivation.
- Basis of PKI

Main methods

- deterministic key derivation
    - allows for minimal key storage
- Key derivation with additional secret
    - allows for easy key erasion
    - additional key doesn't need 256bit entropy
- one-way derivation; to avoid leaking master keys
- combination of other methods can lead to unlinkable keys