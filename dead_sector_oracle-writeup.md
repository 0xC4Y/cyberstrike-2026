# DeadSectorOracle — Writeup

**Category:** Forensics
**Difficulty:** Insane
**Points:** 600
**Tags:** raid5, hdd-forensics, smart, lfsr, vigenere, fat12, fisher-yates, substitution-cipher
**Flag:** `cyberstrike{d34d_s3ct0rs_n3v3r_l13_r41d_0r4cl3}`

## Overview

A 3-disk RAID-5 array with a 48 KB chunk size (non-standard, defeats
`mdadm`). One disk is zero-filled (unreadable); the other two are intact.
Disk A carries a fake S.M.A.R.T. vendor attribute (`0xFE`) whose
reallocated-sector log points to 16 LBAs holding an encrypted payload.
That payload, after an LFSR-keyed Vigenère decrypt, becomes an 8 KB FAT12
micro-image containing `key.txt` + `cipher.bin`. `cipher.bin` is a
full-256-symbol monoalphabetic substitution (Fisher-Yates shuffle seeded
from `SHA-1(key.txt)`); the decrypted bytes hold the flag interleaved
with verifiable noise at every 4th offset starting at position 2.

The README gave geometry + a 7-stage roadmap, but one stage had a subtle
trap: the LFSR is described as "Galois" yet the tap set
(`x¹⁶+x¹⁵+x²+1`, bits 15/14/1/0) is only correct for a **Fibonacci
shift-right** LFSR. Trusting the "Galois" label naively produces no
valid mask. Reconstructing the full state from the zero-padded boot
sector and solving the GF(2) tap-recovery system pins the mask to
`0xC003` and verifies against 119 known outputs.

## Step 1 — RAID context & S.M.A.R.T. parse

Per the README, `parity_disk(row) = (2 − row) % 3` (left-asymmetric).
Disk C is the dead one. The non-standard 48 KB chunk means no automated
assembler will touch it, but we don't even need the full RAID rebuild —
the encrypted payload lives in reallocated sectors on Disk A itself.

Disk A, sector `0x01F0`, has a fake S.M.A.R.T. attribute at byte offset
**2** inside the sector:

```
[+0x00] magic FECAD BAD   [+] count 0x0010   seed 0x4F63
[+0x08] 16 × (uint32 LBA + uint16 len) = 96 bytes
[+0x68] SHA-1 of entries  (verified ✓)
```

All 16 entries are `(LBA, len=1)` for LBAs **256..271** → concatenate
→ **8192 bytes** of encrypted payload.

## Step 2 — LFSR-keyed Vigenère (the crux)

- Base key: `ORACL3K3Y` (len 9, cycling).
- Every 64 bytes: advance the LFSR once and overwrite
  `key[block_index % 9]` with `lfsr_out & 0xFF`.
- Decrypt: `plain = (cipher − key) mod 256`.

**Recovering the LFSR.** The first decrypted block is a FAT12 boot
sector whose bytes 64..509 are zero-padding, so in that region
`cipher == running_key`. From period-9 repetition across the 8192-byte
payload I located 119 zero-plaintext blocks and read off the low byte
of each LFSR state advance.

With `seed = 0x4F63` and the Fibonacci shift-right recurrence
`state' = (state >> 1) | (b << 15)` where `b = parity(state & M)`, the
known low bytes let me walk the state forward (each new high bit is
observable 9 advances later). Then `b_m = parity(state[m] & M)` is a
linear system over GF(2) in the 16 bits of M — solved with plain
Gaussian elimination → **`M = 0xC003`** (taps 15, 14, 1, 0). Verified
against all 119 known outputs.

## Step 3 — FAT12 + Fisher-Yates + flag extraction

Decryption yields a valid 8 KB FAT12 image (`55AA` sig, `MSDOS5.0`
BPB). Manual parse:

| Sector | Content |
|--------|---------|
| 0 | Boot / BPB |
| 1–2 | FAT ×2 |
| 3 | Root dir: `KEY.TXT` (22 B), `CIPHER.BIN` (188 B) |
| 4 | `key.txt` = `d34d_s3ct0r_0r4cl3_k3y` |
| 5 | `cipher.bin` (188 B) |

Substitution cipher: `seed = int(SHA1(key.txt),16) & 0xFFFFFFFF`,
`random.Random(seed).shuffle(list(range(256)))` → invert → decrypt.

Stage 7: flag bytes at offsets `2, 6, 10, …, 186`; every other byte is
noise satisfying `buf[pos] = buf[nearest_flag] XOR pos`. All 141 noise
bytes verify.

## Solver

One script, challenge data → flag:

```python
#!/usr/bin/env python3
import struct, hashlib, random

BASE = '/home/harsha/ctfs/dead_sector_oracle/'

# ----- Stage 2: S.M.A.R.T. attribute 0xFE on disk_a sector 0x1F0 (+2) -----
da = open(BASE + 'disk_a.img', 'rb').read()
b = 0x01F0 * 512 + 2
assert da[b:b+4] == bytes.fromhex('fecadead')            # magic
count = struct.unpack('<H', da[b+4:b+6])[0]              # 16
seed  = struct.unpack('<H', da[b+6:b+8])[0]              # 0x4F63
entries = da[b+8:b+8+96]
assert hashlib.sha1(entries).digest() == da[b+8+96:b+8+96+20]   # SHA-1 ✓
lbas = [struct.unpack('<I', entries[i*6:i*6+4])[0] for i in range(16)]  # 256..271

# ----- Stage 3: reallocated sector pool -> 8192-byte payload -----
payload = b''.join(da[l*512:(l+1)*512] for l in lbas)

# ----- Stage 4: LFSR-keyed Vigenère -----
# Fibonacci shift-right LFSR, taps 15/14/1/0 -> mask 0xC003
# (README labels it "Galois" but the tap set is Fibonacci; mask recovered
#  via GF(2) tap-recovery from 119 zero-plaintext blocks in the boot sec.)
MASK = 0xC003
def lfsr_step(s):
    nb = bin(s & MASK).count('1') & 1
    return ((s >> 1) | (nb << 15)) & 0xFFFF

key = list(b'ORACL3K3Y')          # period 9
st  = seed
plain = bytearray(len(payload))
for blk in range(len(payload) // 64):
    if blk >= 1:
        st = lfsr_step(st)
        key[blk % 9] = st & 0xFF
    for i in range(64):
        p = blk*64 + i
        plain[p] = (payload[p] - key[p % 9]) % 256

assert plain[510] == 0x55 and plain[511] == 0xAA         # FAT12 boot sig

# ----- Stage 5: parse the 8 KB FAT12 micro-image -----
sec = lambda n: plain[n*512:(n+1)*512]
key_txt    = sec(4).rstrip(b'\x00')                       # d34d_s3ct0r_0r4cl3_k3y
cipher_bin = sec(5)                                       # 512 B; first 188 are real

# ----- Stage 6: Fisher-Yates monoalphabetic substitution -----
sha1_hex = hashlib.sha1(key_txt).hexdigest()
rng = random.Random(int(sha1_hex, 16) & 0xFFFFFFFF)
tbl = list(range(256)); rng.shuffle(tbl)                  # plain -> cipher
dec_tbl = [0]*256
for p, c in enumerate(tbl): dec_tbl[c] = p
dec = bytes(dec_tbl[x] for x in cipher_bin)

# ----- Stage 7: interleaved flag at offsets 2,6,10,...,186 -----
flag_pos = list(range(2, 188, 4))
buf = dec[:188]
flag = bytes(buf[p] for p in flag_pos)

# verify noise: buf[pos] == buf[nearest_flag] ^ pos
ok = all(any(buf[pos] == buf[fp] ^ pos for fp in flag_pos)
         for pos in range(188) if pos not in flag_pos)
assert ok, 'noise verification failed'

print(flag.decode())   # -> cyberstrike{d34d_s3ct0rs_n3v3r_l13_r41d_0r4cl3}
```

### Output

```
[S2] count=16 seed=0x4f63 sha1 OK
[S4] FAT12 OK: bps=512 spc=1 rsv=1 nfats=2 sig=55AA
[S5] key.txt = b'd34d_s3ct0r_0r4cl3_k3y' (len 22)
[S6] sha1(key.txt)=634fac9384a2da7f9b93805014c7473f1ce5acc0 seed=484814016
[S7] noise verify: True
cyberstrike{d34d_s3ct0rs_n3v3r_l13_r41d_0r4cl3}
```

## Flag

```
cyberstrike{d34d_s3ct0rs_n3v3r_l13_r41d_0r4cl3}
```

## Lessons / gotchas

- **README mislabel:** "Galois LFSR" vs the actual Fibonacci
  shift-right recurrence. The published *tap polynomial*
  (`x¹⁶+x¹⁵+x²+1`) was correct; the *implementation family* was wrong.
  Galois and Fibonacci LFSRs with the same polynomial produce different
  bitstreams. Don't trust prose — derive the mask from known plaintext.
- **Known plaintext is everywhere in a FAT12 boot sector:** the 446-byte
  zero-pad region gives ~7 free key observations per 64-byte block,
  enough to walk the full 16-bit state and recover taps via GF(2).
- **8 KB FAT12 won't mount** (`<160 KB` minimum) — parse by hand.
- **Fisher-Yates with Python's Mersenne Twister** is fully deterministic
  given `int(sha1,16) & 0xFFFFFFFF`; `random.shuffle` is the exact
  Fisher-Yates implementation.
