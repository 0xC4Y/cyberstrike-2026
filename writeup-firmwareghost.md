---
title: "FirmwareGhost"
ctf: "CyberStrike"
date: 2026-07-10
category: reverse
difficulty: hard
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# FirmwareGhost

## Summary

A 256-byte raw ARM Cortex-M4 firmware image contains a vector table, a short Thumb-2 reset handler that loads a stream cipher seed (`0xa5`) and polynomial (`0xb8`), and 45 bytes of encrypted flag data at offset `0x20`. The cipher is an 8-bit Galois LFSR. Known-plaintext attack using `cyberstrike{` recovers the LFSR parameters, and XORing the full ciphertext stream decrypts the flag.

## Solution

### Step 1: Parse the vector table and identify code vs data

The firmware is a flat blob loaded at `0x08000000`. The first 8 bytes are the Cortex-M vector table:

| Offset | Value | Meaning |
|--------|-------|---------|
| 0x00 | `0x20020000` | Initial SP |
| 0x04 | `0x08000009` | Reset handler (Thumb bit set) |

The reset handler at `0x08000008` (offset 0x08) is Thumb-2 code. Disassembly reveals:

```
0x08000008: push.w  {r4, lr}
0x0800000c: mov.w   r0, #0xa5      ; LFSR seed
0x08000010: mov.w   r1, #0xb8      ; LFSR polynomial
0x08000014: movs    r0, #0
0x08000016: b       <loop>          ; branch to cipher loop
```

The constants `0xa5` (seed) and `0xb8` (polynomial) are the key parameters. The encrypted flag data starts at offset `0x20` and is 45 bytes long (offsets `0x20`–`0x4C`), with `0x00` padding after.

### Step 2: Recover the stream cipher via known-plaintext attack

Using the known flag prefix `cyberstrike{` (12 bytes), XOR with the first 12 ciphertext bytes to extract the keystream, then identify the LFSR:

```python
#!/usr/bin/env python3
"""FirmwareGhost — Galois LFSR stream cipher recovery via known plaintext."""

# Encrypted flag data at offset 0x20 (44 bytes) + 1 byte at 0x4C
enc = bytes.fromhex(
    '890ce024ea3f5261d88b15437d6f66da'
    'd4fb54bb27f82ffc7dadc5f1bab70956'
    '9162a37b40766dd86a1b9bdb'
)
extra = 0xb2  # byte at offset 0x4C

known = b'cyberstrike{'

# Step 1: Extract keystream from known plaintext
ks = bytes([e ^ k for e, k in zip(enc, known)])
print(f"Keystream: {ks.hex()}")

# Step 2: Identify as 8-bit Galois LFSR with seed=0xa5, poly=0xb8
# (from the reset handler constants, confirmed by the keystream)
def galois_lfsr_decrypt(ciphertext, seed=0xa5, poly=0xb8):
    state = seed
    dec = []
    for ct_byte in ciphertext:
        out = state & 1
        state >>= 1
        if out:
            state ^= poly
        dec.append(ct_byte ^ state)
    return bytes(dec), state

flag, final_state = galois_lfsr_decrypt(enc)
print(f"Decrypted: {flag.decode()}")

# Step 3: Decrypt the closing brace (byte 0x4C = 0xB2)
out = final_state & 1
final_state >>= 1
if out:
    final_state ^= 0xb8
closing = extra ^ final_state
assert closing == ord('}'), f"Expected '}}', got {chr(closing)}"

print(f"FLAG: {flag.decode()}{chr(closing)}")

# Step 4: Verify by re-encryption
state = 0xa5
reenc = []
for d in flag:
    out = state & 1
    state >>= 1
    if out:
        state ^= 0xb8
    reenc.append(d ^ state)
out = state & 1
state >>= 1
if out:
    state ^= 0xb8
reenc.append(closing ^ state)

assert bytes(reenc[:-1]) == enc
assert reenc[-1] == extra
print("Re-encryption verified: all bytes match")
```

### Step 3: Run the solver

```bash
python3 solve.py
# Keystream: ea758241984c2613b1e07038
# Decrypted: cyberstrike{aaaa1111bbbb2222cccc3333dddd4444
# FLAG: cyberstrike{aaaa1111bbbb2222cccc3333dddd4444}
# Re-encryption verified: all bytes match
```

## Flag

```
cyberstrike{aaaa1111bbbb2222cccc3333dddd4444}
```

## Notes

- **No ELF, no symbols**: The firmware is a raw 256-byte blob with no section headers. The load address (`0x08000000`) and architecture (ARM Cortex-M4 Thumb-2) must be supplied manually. Orientation starts from the vector table at offset 0x00.
- **Vector table**: Only 2 entries are meaningful — initial SP (`0x20020000`) and reset handler (`0x08000009`, Thumb bit set). The remaining "entries" at offsets 0x08+ are actually the code itself, not interrupt vectors.
- **Stream cipher identification**: The reset handler loads `r0 = 0xa5` and `r1 = 0xb8` as cipher parameters. Known-plaintext attack with `cyberstrike{` confirms these are the seed and polynomial of an 8-bit Galois LFSR: `state >>= 1; if (old_bit) state ^= 0xb8`.
- **Encrypted data layout**: 44 bytes of ciphertext at offset `0x20`–`0x4B`, plus 1 byte (`0xB2`) at offset `0x4C` that decrypts to the closing `}`. Bytes `0x4D`–`0xFF` are zero padding.
- **The disassembly is small**: Only ~20 bytes of actual Thumb-2 code (the reset handler + cipher loop). The rest is the vector table and encrypted data. The challenge is recognizing the LFSR pattern from the two constants and the code structure, not navigating a large binary.
