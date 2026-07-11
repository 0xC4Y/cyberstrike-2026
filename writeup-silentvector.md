---
title: "SilentVector"
ctf: "CyberStrike CTF"
date: 2026-07-10
category: misc
difficulty: insane
points: 600
flag_format: "cyberstrike{...}"
author: "retr0"
---

# SilentVector

## Summary

A multi-stage crypto chain: Alice's DH private key is hidden under an XOR mask keyed by an MD5 hash of a passphrase (`ghost_protocol_v2`, given in the challenge text). Recovering her private key allows computing the DH shared secret, from which an AES-256-CBC key is derived via SHA256. The decoy RSA block is irrelevant.

## Solution

### Step 1: Chain the four stages

The challenge provides a JSON file with DH parameters, both public keys, Bob's private key, Alice's XOR-obfuscated private key, and the AES-encrypted flag. The hints spell out the exact steps; the only "puzzle" is identifying the passphrase — stated in the challenge description: "the mask key comes from a legacy hashing method seeded by an old protocol codename (ghost_protocol_v2)".

1. **Unmask Alice's private key**: `MD5("ghost_protocol_v2")` = 16 bytes; repeat to 32 bytes, XOR with the obfuscated blob.
2. **Compute DH shared secret**: `pow(bob_public, alice_private, p)` — verified against `pow(alice_public, bob_private, p)` (Bob's private key is given to confirm correctness; either path works).
3. **Derive AES key**: `SHA256(shared_secret.to_bytes(32) + passphrase_bytes)`.
4. **Decrypt**: AES-256-CBC with the given IV.

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

passphrase = b"ghost_protocol_v2"

# 1. Recover Alice's private key
mask = hashlib.md5(passphrase).digest() * 2  # 32 bytes
obfuscated = bytes.fromhex("5897438c22b90c5983b3b7ea4e08d377c2d86682a04ea2ea16d1325f8acd32a5")
alice_private = int.from_bytes(bytes(a ^ b for a, b in zip(obfuscated, mask)), "big")

# 2. Compute DH shared secret
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74
bob_public = 0x62036aa669be0ef42e6700540b474be140b695625e55978b780e4174e2036dc4
shared_secret = pow(bob_public, alice_private, p)

# 3. Derive AES key
aes_key = hashlib.sha256(shared_secret.to_bytes(32, "big") + passphrase).digest()

# 4. Decrypt
iv = bytes.fromhex("770062882cbf9439f23a544291c18cf0")
ct = bytes.fromhex("5aff19b69103f080f6dd0b9253b6b063c5b20e81f41a98e0c731fdbe095c2c569ded9c79ae769a96d1c00a841cb59de7")
print(unpad(AES.new(aes_key, AES.MODE_CBC, iv=iv).decrypt(ct), 16).decode())
```

```
cyberstrike{RSA_m33ts_AES_in_th3_d4rk}
```

The `decoy_rsa` block (hint #5) is the named decoy — none of its fields are used.

## Flag

```
cyberstrike{RSA_m33ts_AES_in_th3_d4rk}
```
