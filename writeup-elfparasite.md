---
title: "ELFParasite"
ctf: "CyberStrike"
date: 2026-07-11
category: reverse
difficulty: medium
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# ELFParasite

## Summary

A Mach-O 64-bit arm64 binary contains a hidden pre-main "parasite" routine that derives a 4-byte XOR keystream from `CRC32(argv[0])` and decrypts a 39-byte payload stored in `__TEXT.__const`. Running it under its own path `./challenge` yields a 4-byte key whose low-3-of-4 byte pattern (`0xe1, 0xfe, 0x1f, 0x30`) decrypts the flag.

## Solution

### Step 1: Identify the cipher

`func.1000004f8` is the "parasite" — a near-copy of `main` that:

1. Builds a 256-entry CRC32 table at `__DATA+0x28` using polynomial `0xEDB88320`.
2. Computes the standard CRC32 of `argv[0]` (init `0xFFFFFFFF`, final XOR `0xFFFFFFFF`).
3. For each of the 39 ciphertext bytes at `__TEXT.__const` (vaddr `0x1000006d8`):
   `plaintext[i] = ciphertext[i] ^ crc32_le_bytes[i & 3]`

The 39-byte ciphertext extracted from `__TEXT.__const`:

```
fca95955eda34f42f6bb5e4bfae15d55aeb65e01f9b50a56fae15d55aeb65e01f9b50a56fae146
```

### Step 2: Brute-force the argv[0]-derived key

The flag must start with `cyberstrike{` (11 bytes), so the first 4 keystream bytes are:

```
crc_bytes[0] = 0xfc ^ ord('c') = 0x9f
crc_bytes[1] = 0xa9 ^ ord('y') = 0xd0
crc_bytes[2] = 0x59 ^ ord('b') = 0x3b
crc_bytes[3] = 0x55 ^ ord('e') = 0x30
```

i.e. CRC32 little-endian = `0x303bd09f`. Brute-forcing a few plausible `argv[0]` strings against `CRC32()` gives a clean ASCII hit for `./challenge` (the path the program is normally invoked from), which is also what the parasite itself would see at runtime.

### Step 3: Decrypt

```python
ct = bytes.fromhex("fca95955eda34f42f6bb5e4bfae15d55aeb65e01f9b50a56fae15d55aeb65e01f9b50a56fae146")

def crc32(s):
    tbl = [0]*256
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        tbl[i] = c
    c = 0xFFFFFFFF
    for b in s:
        c = tbl[(c ^ b) & 0xff] ^ (c >> 8)
    return c ^ 0xFFFFFFFF

crc = crc32(b"./challenge")        # 0x303bd09f
key = crc.to_bytes(4, "little")
pt  = bytes(ct[i] ^ key[i & 3] for i in range(len(ct)))
print(pt.decode())
```

## Flag

```
cyberstrike{e1fe1fe1fe1fe1fe1fe1fe1fe1}
```
