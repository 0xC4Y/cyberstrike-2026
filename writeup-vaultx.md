---
title: "Vault-X: Fragmented Trust"
ctf: "CyberStrike"
date: 2026-07-10
category: reverse
difficulty: hard
points: 475
flag_format: "cyberstrike{...}"
author: "retr0"
---

# Vault-X: Fragmented Trust

## Summary

A stripped x86-64 ELF binary authenticates via `read(0, buf, 16)` (raw bytes, not `scanf`/`fgets`), applies two layered transforms to the 16-byte key, then `memcmp`s the result against a hardcoded target. The flag is stored XOR-encrypted in `.rodata` and is printed on success. Anti-debug uses `ptrace(PTRACE_TRACEME)`. The key contains a null byte and other non-printable chars, so it must be piped in — this is the "may not behave as expected with standard input methods" hint.

## Solution

### Step 1: Reverse the two transforms and decrypt the flag statically

Static analysis of the disassembly reveals:

- **Transform 1** (`0x4011f6`): four segment operations on 4-byte groups of the input buffer
  - Bytes 0-3: `buf[i] ^= 0x23`
  - Bytes 4-7: `buf[i] = (buf[i] + i) ^ 0x55`
  - Bytes 8-11: `buf[i] = ROL1(buf[i]) ^ 0xAA` (rotate left 1 bit)
  - Bytes 12-15: `buf[i] = buf[i] - 3*i`
- **Transform 2** (`0x40130b`): a fixed permutation `perm = [5,2,9,0,7,1,12,3,14,6,10,4,15,8,13,11]` — reads `buf[perm[i]]` into a reordered output
- **Target** (from `memcmp`): `91 23 77 ab 10 55 66 9f 42 88 19 fe 33 72 60 a1`
- **Encrypted flag** (32 bytes in `.rodata`, XORed with `0x55` to print)

Both the key and the flag are recoverable purely from static data — no dynamic execution needed.

```python
#!/usr/bin/env python3
"""Vault-X: Fragmented Trust — static solve (no execution of the binary required)."""

# --- Hardcoded data extracted from the disassembly ---

# memcmp target (little-endian movabs: 0x9f665510ab772391, 0xa1607233fe198842)
target = bytes([
    0x91, 0x23, 0x77, 0xab, 0x10, 0x55, 0x66, 0x9f,
    0x42, 0x88, 0x19, 0xfe, 0x33, 0x72, 0x60, 0xa1,
])

# Permutation from transform2: out[i] = buf[perm[i]]
perm = [5, 2, 9, 0, 7, 1, 12, 3, 14, 6, 10, 4, 15, 8, 13, 11]

# Encrypted flag bytes (little-endian movabs values from 0x4014e5..0x401519)
enc_flag = bytes([
    0x36, 0x2c, 0x37, 0x30, 0x27, 0x26, 0x21, 0x27,
    0x3c, 0x3e, 0x30, 0x2e, 0x23, 0x61, 0x20, 0x39,
    0x62, 0x0a, 0x2d, 0x0a, 0x33, 0x27, 0x61, 0x32,
    0x27, 0x3b, 0x66, 0x3b, 0x62, 0x66, 0x31, 0x28,
])

# --- Reverse transform2 (permutation) ---
# out[i] = buf[perm[i]]  =>  buf[perm[i]] = out[i]
after_t1 = [0] * 16
for i in range(16):
    after_t1[perm[i]] = target[i]

# --- Reverse transform1 (each segment) ---
def ror1(b):
    return ((b >> 1) | ((b & 1) << 7)) & 0xFF

key = [0] * 16
for i in range(4):            # loop1: buf[i] ^= 0x23
    key[i] = after_t1[i] ^ 0x23
for i in range(4, 8):         # loop2: buf[i] = (buf[i]+i) ^ 0x55
    key[i] = ((after_t1[i] ^ 0x55) - i) & 0xFF
for i in range(8, 12):        # loop3: buf[i] = ROL1(buf[i]) ^ 0xAA
    key[i] = ror1(after_t1[i] ^ 0xAA)
for i in range(12, 16):       # loop4: buf[i] = buf[i] - 3*i
    key[i] = (after_t1[i] + 3 * i) & 0xFF

key_bytes = bytes(key)

# --- Decrypt the flag (XOR with 0x55) ---
flag = bytes(b ^ 0x55 for b in enc_flag).rstrip(b"\x00").rstrip(b"U")

print(f"key  = {key_bytes.hex()}")
print(f"key  = {key_bytes!r}")
print(f"flag = {flag.decode()}")

# --- Optional: verify by feeding the key to the binary ---
# import sys; sys.stdout.buffer.write(key_bytes + b"\n")
# | ./vaultx
```

### Step 2: Verify against the live binary

The recovered key contains a null byte and non-printable chars, so it must be piped (not typed). This is the "standard input methods" warning in the challenge description.

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'\x88\x76\x00\xbc\xa7\xbf\xd7\x3e\x6c\xee\xd9\x85\x8a\x87\x6c\x60' + b'\n')" | ./vaultx
# [Vault-X] Enter key: [+] Flag: cyberstrike{v4ul7_x_fr4grn3n73d}U
```

The trailing `U` is the null terminator XORed with `0x55` — not part of the flag.

## Flag

```
cyberstrike{v4ul7_x_fr4grn3n73d}
```

## Notes

- **Anti-debug**: `ptrace(PTRACE_TRACEME, 0, 1, 0)` at `0x4013f4`; returns `-1` if a tracer is already attached, causing `exit(1)`. Bypass with `LD_PRELOAD` shim or patch the `cmp $0xffffffffffffffff` at `0x4013f9`.
- **Input method**: `read(0, buf, 16)` reads exactly 16 raw bytes — no null-termination, no newline stripping. A second `read(0, &c, 1)` consumes the trailing newline. The key byte at index 2 is `0x00`, so `scanf("%s")` or typing it in a terminal is impossible; piping bytes is required.
- **Transform 1** uses four *different* operations on consecutive 4-byte segments — the "Fragmented Trust" name hints at this fragmented/non-uniform transformation.
- **The flag is XOR-encrypted in `.rodata`** and independent of the key check, so it can be decrypted directly without reversing the key validation at all — the key reversal above is shown for completeness.
