---
title: "Aetheric Sync"
ctf: "CSC-SNIST"
date: 2026-07-10
category: crypto
difficulty: easy
points: 100
flag_format: "cyberstrike{...}"
author: "retr0"
---

# Aetheric Sync

## Summary

Three encrypted packets share a single LCG-based XOR stream cipher keystream that is **not reset** between packets. The first packet is a known handshake, which reveals 8 consecutive LCG states — enough to recover the LCG parameters `a` and `c`, regenerate the full keystream, and decrypt all packets. The decrypted packets contain RSA parameters with a near-full-size public exponent `e` (implying a tiny `d`), enabling Wiener's continued-fraction attack to decrypt the final ciphertext and recover the flag.

## Solution

### Step 1: Recover the LCG keystream and parameters from the known handshake

The first packet is always `{"status": "SYNC", "version": "v2.0.7", "checksum": "0x5f3759df"}`. XORing it with `packet_0`'s ciphertext yields 65 bytes of keystream, containing 8 full 8-byte LCG states. From three consecutive states, solve for `a` and `c`:

```
a = (s3 - s2) * (s2 - s1)^(-1) mod 2^64
c = s2 - a * s1 mod 2^64
```

The LCG continues across packets (not reset), so the keystream for `packet_1` begins where `packet_0` left off (state 10).

### Step 2: Decrypt all packets and break the RSA

With `a` and `c` known, generate the full keystream and decrypt all three packets:

- **packet_0**: handshake (verification)
- **packet_1**: `{"status": "ACTIVE", "rsa_n": ..., "rsa_e": ...}` — 1024-bit `n`, 1023-bit `e`
- **packet_2**: `{"status": "SECURE", "data": "0x..."}` — RSA ciphertext

The public exponent `e` is nearly as large as `n`, implying `d` is very small. Wiener's attack on the continued fraction expansion of `e/n` recovers `d` (200-bit, well under `n^0.25`), factors `n`, and decrypts the ciphertext.

```python
import json
from math import gcd

# --- Load packets ---
with open("traffic.log") as f:
    traffic = json.load(f)
packets = {k: bytes.fromhex(v) for k, v in traffic.items()}

# --- Step 1: Known-plaintext attack on LCG keystream ---
handshake = b'{"status": "SYNC", "version": "v2.0.7", "checksum": "0x5f3759df"}'
ks_known = bytes(a ^ b for a, b in zip(packets["packet_0"], handshake))
MOD = 2**64

# Extract 8 full LCG states from first 64 bytes of keystream
states = [int.from_bytes(ks_known[i:i+8], 'big') for i in range(0, 64, 8)]

# Recover LCG parameters a, c from consecutive states
a = c = None
for i in range(len(states) - 2):
    diff = (states[i+1] - states[i]) % MOD
    if diff % 2 == 1:
        a = ((states[i+2] - states[i+1]) * pow(diff, -1, MOD)) % MOD
        c = (states[i+1] - a * states[i]) % MOD
        if all((a * states[j] + c) % MOD == states[j+1] for j in range(len(states)-1)):
            break

# --- Step 2: Generate keystream and decrypt all packets ---
def gen_keystream(start_state, n_bytes):
    ks, state = b"", start_state
    while len(ks) < n_bytes:
        state = (a * state + c) % MOD
        ks += state.to_bytes(8, 'big')
    return ks

# packet_0 used 9 states (ceil(65/8)); packet_1 starts at state 10
cur = states[7]
for _ in range(2):  # advance to state_9 then state_10
    cur = (a * cur + c) % MOD

for key in ["packet_1", "packet_2"]:
    ct = packets[key]
    ks = gen_keystream(cur, len(ct))
    pt = bytes(x ^ y for x, y in zip(ct, ks))
    data = json.loads(pt)
    print(f"{key}: {data}")
    # Advance state past this packet's states
    for _ in range((len(ct) + 7) // 8):
        cur = (a * cur + c) % MOD

# --- Step 3: Wiener's attack on the RSA ---
n = 98605093148426420969047796800101334940975841011769065299614993534865713370731117401030168888440656373785707310817026439533833658621668458991099661533561722171775378655997143850507448384803470069876020307000404757016397455159753303332226456972884642628466281532211483650810086256495249270381076756344886329239
e = 47957675688220606023351872048938025184608065932661426054037181680201217486785101456882651716321705781784175491401634524735171832606491963683176709271215562083312836595564117189016481263243475612861331810731076001626152223132206487774141743468643516935826092318347267614917423839346913009644749908943729929295
ct_hex = "8a0f157711d9799adb82b7d66462662a3e74b8b6129a33e59f8595d74718dc658430fabfdfd68b0a0716e84b699832391b140ddf4614dabd305aa3b12b18b2200c5ff2e5b2278ed553211be4069e5cc4445d2d662c2658ed412cc9dea93f932855a8bb190f104f1d1fab6ad84bc30616ac993595274a8e10dd7b52827a3c4352"

def is_perfect_square(n):
    s = int(n**0.5)
    for ds in (s-1, s, s+1):
        if ds*ds == n:
            return ds
    return None

# Continued fraction of e/n
cf, a_val, b_val = [], e, n
while b_val:
    cf.append(a_val // b_val)
    a_val, b_val = b_val, a_val - cf[-1] * b_val

h_prev, h, k_prev, k = 1, cf[0], 0, 1
for i in range(1, len(cf)):
    h_prev, h = h, cf[i]*h + h_prev
    k_prev, k = k, cf[i]*k + k_prev
    if (e*h - 1) % k != 0:
        continue
    phi = (e*h - 1) // k
    s = n - phi + 1  # p + q
    disc = s*s - 4*n
    sq = is_perfect_square(disc)
    if sq and (s+sq)//2 * (s-sq)//2 == n:
        d = h
        pt = pow(int(ct_hex, 16), d, n)
        flag = pt.to_bytes((pt.bit_length()+7)//8, 'big').decode()
        print(f"FLAG: {flag}")
        break
```

Actual output:

```
packet_1: {"status": "ACTIVE", "rsa_n": 9860..., "rsa_e": 4795...}
packet_2: {"status": "SECURE", "data": "0x8a0f..."}
FLAG: cyberstrike{a3th3ric_sync_v2_w13n3r_4nd_lcg_9f3c21}
```

## Flag

```
cyberstrike{a3th3ric_sync_v2_w13n3r_4nd_lcg_9f3c21}
```
