---
title: "FlatState"
ctf: "CyberStrike"
date: 2026-07-10
category: reverse
difficulty: hard
points: 250
flag_format: "cyberstrike{...}"
author: "anomalyco"
---

# FlatState

## Summary

A 64-bit ELF "validator" whose success path is hidden behind control-flow flattening. The natural per-character check loop is shredded into a state-machine dispatcher, the per-byte target is derived at runtime from a 36-byte `FLAG_KEY` via an xorshift64* PRNG, and the program prints a constant decoy token (`cyberstrike{pdjorka3bdvr99b3pdjs}`) on the "wrong" branch. Reconstructing the PRNG and inverting the per-byte check reveals the real flag.

## Solution

### Step 1: Triage and notice the decoy

`strings` shows the BUILD METADATA mentioning `derive_flag()`, `verify_checksum()`, and a `FLAG_KEY[]`. Running the binary with any input prints `Wrong. computed token: cyberstrike{pdjorka3bdvr99b3pdjs}`. Because the token is constant regardless of input length or content, it is a decoy emitted from the failure branch (`call 4013f0` with key `0xd00df1a7`); the real flag is the input that takes the "Correct" branch.

### Step 2: Recover the state machine and per-byte check

`objdump -d -M intel` shows the success path lives at `0x401080` and the per-byte check is a small loop at `0x401158`–`0x401182` driven by `esi` (an OR-accumulator). Just before it, a 36-iteration loop at `0x4010f0`–`0x40112a` runs an xorshift64* generator seeded with `(rdx, rdi) = (0x4e3a881e28ed958c, 0x2545f4914f6cdd1d)` and XORs each output byte with a byte from `FLAG_KEY[0x24]` at `0x4020a0`, producing a 36-byte target buffer on the stack.

The per-byte check (with `derived_buf[i]` = the PRNG output) is:

```
cl  = input[i] ROL 8 ((i+2) mod 8)
ecx = cl
ecx = ecx + (i XOR 0x5f)
eax = i + 4*(3*i) + 9   = 13i + 9
eax = eax XOR ecx
al  = al XOR derived_buf[i]
esi |= al           // require esi == 0 at the end
```

For each `i` we brute-force the unique byte that makes `al == 0`, then reassemble. Verification: the resulting 36-byte string `cyberstrike{fl4tt3n3d_st4t3_m4ch1n3}` is accepted by the binary.

```python
#!/usr/bin/env python3
import struct

MASK, M32 = 0xff, 0xffffffff

def rol8(b, n):
    n %= 8
    return ((b << n) | (b >> (8 - n))) & MASK

with open("flatstate", "rb") as f:
    data = f.read()

# Locate FLAG_KEY (virtual 0x4020a0 -> file offset via PT_LOAD)
e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
e_phentsize = struct.unpack("<H", data[0x36:0x38])[0]
e_phnum = struct.unpack("<H", data[0x38:0x3a])[0]
target = 0x4020a0
for i in range(e_phnum):
    o = e_phoff + i*e_phentsize
    if struct.unpack("<I", data[o:o+4])[0] != 1: continue
    p_off  = struct.unpack("<Q", data[o+8:o+16])[0]
    p_vaddr= struct.unpack("<Q", data[o+16:o+24])[0]
    p_fsz  = struct.unpack("<Q", data[o+32:o+40])[0]
    if p_vaddr <= target < p_vaddr + p_fsz:
        FLAG_KEY = data[p_off + (target - p_vaddr): p_off + (target - p_vaddr) + 0x24]
        break

# xorshift64* PRNG -> 36-byte target buffer
s1 = 0x4e3a881e28ed958c
s0 = 0x2545f4914f6cdd1d
MASK64 = (1<<64)-1
derived = bytearray(0x24)
for i in range(0x24):
    s1 = (s1 ^ (s1 >> 12)) & MASK64
    rcx = (s1 << 25) & MASK64
    rcx = (rcx ^ s1) & MASK64
    s1  = ((rcx >> 27) ^ rcx) & MASK64
    cl  = ((s1 * s0) >> 33) & 0xff
    derived[i] = cl ^ FLAG_KEY[i]

# Invert per-byte check by brute force
flag = bytearray()
for i in range(0x24):
    for cand in range(256):
        cl8 = rol8(cand, (i+2) & 7)
        ecx = cl8
        ecx = (ecx + (i ^ 0x5f)) & M32
        eax = (i + 4*(3*i) + 9) & M32
        eax = (eax ^ ecx) & M32
        al  = (eax ^ derived[i]) & 0xff
        if al == 0:
            flag.append(cand); break
print(flag.decode())
```

### Step 3: Confirm

```
$ printf "cyberstrike{fl4tt3n3d_st4t3_m4ch1n3}\n" | ./flatstate
FlatState v1.0
Enter password: Correct! Submit your input as the flag.
```

## Flag

```
cyberstrike{fl4tt3n3d_st4t3_m4ch1n3}
```
