
For a wallet, user holds a private key on a device.

The privatekey may be generated from a KDF over a secret phrase. 

Usually a wallet is only on one device, and not shared unless user did so. Derived keys can be copied as user wishes. (Compartmentalization of risk; no cross-contamination)

All derived keys are done in the method `HMAC(hash(base_key), deterministic_part, disposable_part)`

The separation of deterministic part and non-deterministic part allows for easy erasing and copying of keys. Erasing takes only a few metadata, copying takes a only a little too.

Determistic part can be `RoomTarget`

```
enum RoomTarget {
    Group([u8; 32]),
    DM([u8; 32]),
    Note
}
```

Non-deterministic part can be a session ID in 256bits, which is information-theoretic secure when it's erased.

A wallet contains `(base_key, [disposable_keys])` which is needed to recover all derived keys. 

For DMs, usually room symmetric base key can be derived in a secret sharing way in either post quantum or pre quantum way, using public components of both parties. (Secret sharing, or Key Encapsulation)

KDFs are avoided whenever possible. Share base keys of 256bits. 

Group keys are simply 256bit random generated, and distributed on demand.

Ratchet encryption is avoided due to endless synchronization issues.

Easy creation of unlinkable invite codes, and unlinkable identities. 