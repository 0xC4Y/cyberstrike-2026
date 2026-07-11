---
title: "ECDSA Echo"
ctf: "CSC-SNIST"
date: 2026-07-10
category: crypto
difficulty: easy
points: 100
flag_format: "cyberstrike{...}"
author: "retr0"
---

# ECDSA Echo

## Summary

A drone's communication log contains 240 ECDSA signatures on secp256k1. Ten pairs share the same `r` value (nonce reuse), but only the `PRIMARY KEYROTATION` pair has valid signatures — the nine `AUX LINKSYNC` pairs are forged honeypots. Recovering the private key `d` from the valid nonce-reuse pair, then deriving the AES key as `SHA256(str(d))`, decrypts the `encrypted_flag` field via AES-256-CBC.

## Solution

### Step 1: Find nonce reuse and identify the valid pair

Group all 240 signatures by `r` value. Ten `r` values appear twice (nonce reuse). For each pair, attempt private key recovery via `k = (z1−z2)/(s1−s2) mod N` and `d = (s1·k − z1)/r mod N`. Verify each candidate `d` by checking `d·G == pubkey`. Only the `PRIMARY KEYROTATION` pair (ids 220, 221) yields a key whose derived public key matches — the other nine pairs are `AUX LINKSYNC` decoys with forged `s` values that fail ECDSA verification.

### Step 2: Decrypt the encrypted flag

The log file contains top-level fields `encrypted_flag` (64-byte hex) and `iv` (16-byte hex) alongside the signatures. The AES-256-CBC key is `SHA256(str(d))` — the SHA-256 hash of the private key's decimal string representation.

```python
import json, hashlib
from Crypto.Cipher import AES

with open("signatures.log") as f:
    data = json.load(f)

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P = 2**256 - 2**32 - 977
A, B = 0, 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

def mod_inv(v, m): return pow(v, -1, m)
def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1,y1 = p1; x2,y2 = p2
    if x1==x2 and (y1+y2)%P==0: return None
    if x1==x2: m=(3*x1*x1+A)*mod_inv(2*y1,P)%P
    else: m=(y2-y1)*mod_inv((x2-x1)%P,P)%P
    return ((m*m-x1-x2)%P, (m*(x1-(m*m-x1-x2)%P)-y1)%P)
def ec_mul(k,p):
    res=None; curr=p; k=k%N
    while k>0:
        if k&1: res=ec_add(res,curr)
        curr=ec_add(curr,curr); k>>=1
    return res
def verify(z, r, s, Q):
    w = mod_inv(s, N); u1=(z*w)%N; u2=(r*w)%N
    R = ec_add(ec_mul(u1,G), ec_mul(u2,Q))
    return R is not None and R[0]%N == r

def norm(h):
    h = h.lower().lstrip("0x")
    return h if len(h)%2==0 else "0"+h

sigs = data["signatures"]
Q = (int(data["pubkey"][0],16), int(data["pubkey"][1],16))

# Step 1: Find nonce-reuse pairs and recover d
from collections import defaultdict
by_r = defaultdict(list)
for s in sigs:
    by_r[norm(s["r"])].append(s)

d = None
for r_hex, entries in by_r.items():
    if len(entries) < 2: continue
    r = int(r_hex, 16)
    s1 = int(norm(entries[0]["s"]), 16)
    s2 = int(norm(entries[1]["s"]), 16)
    z1 = int(norm(entries[0]["z"]), 16)
    z2 = int(norm(entries[1]["z"]), 16)
    k = ((z1 - z2) * mod_inv((s1 - s2) % N, N)) % N
    cand = ((s1 * k - z1) * mod_inv(r, N)) % N
    if ec_mul(cand, G) == Q:
        d = cand
        print(f"[+] Recovered d from '{entries[0]['message']}'")
        break

# Step 2: Decrypt the flag (AES-256-CBC, key = SHA256(str(d)))
key = hashlib.sha256(str(d).encode()).digest()
ct = bytes.fromhex(data["encrypted_flag"])
iv = bytes.fromhex(data["iv"])
pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
flag = pt.rstrip(b'\x00').decode().rstrip('\t')
print(f"[+] FLAG: {flag}")
```

Actual output:

```
[+] Recovered d from 'Operation Echo Sync: PRIMARY KEYROTATION 3288'
[+] FLAG: cyberstrike{ecdsa_h4rd3n3d_n0nc3_r3us3_h0n3yp0t_5c7d1e}
```

## Flag

```
cyberstrike{ecdsa_h4rd3n3d_n0nc3_r3us3_h0n3yp0t_5c7d1e}
```
