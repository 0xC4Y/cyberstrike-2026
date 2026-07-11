---
title: "BranchFog"
ctf: "CyberStrike"
date: 2026-07-11
category: reverse
difficulty: hard
points: 450
flag_format: "cyberstrike{...}"
author: "anomalyco"
---

# BranchFog

## Summary

A 64-bit ELF password checker whose real per-byte check is buried inside an indirect-dispatch table of four candidate transforms. Two "opaque predicate" helpers are evaluated per byte to compute the table index; constant-folding them collapses the dispatch to a single live function. Inverting that one function over the 34-byte `FLAG_KEY[]` recovers the flag.

## Solution

### Step 1: Triage and notice the decoy

`strings` shows the BUILD METADATA mentioning `derive_flag()`, `verify_checksum()`, and a `FLAG_KEY[]`. Running the binary with any input prints a constant decoy token (`cyberstrike{zss94jnewrs3v0owzood}`) that does not depend on input length or content. The real flag is whatever input takes the "Correct" branch.

### Step 2: Map the dispatch and constant-fold the opaque predicates

`objdump -d -M intel` shows the per-byte loop at `0x4013fa`–`0x401447`. For each index `i` it:

1. Loads `input[i]` into `r13`.
2. Calls `0x401166(r13 + i)` → result in `r15`.
3. Calls `0x401180(i*i + r13)` → result in `eax`.
4. Computes `index = (eax + 2*r15) & 3` and `call [rsp + index*8]` against the four function pointers `0x4011a9, 0x4011af, 0x401196, 0x4011a9` (decoys).
5. `al ^= FLAG_KEY[i]`, then `ebp |= al` (must end at 0).

Both helpers are opaque predicates — they always return the same constant:

- `0x401166`: `((rdi-1)*rdi) & 1`. Since `rdi*(rdi-1)` is always even, `^1 & 1 = 1`. → always `1`.
- `0x401180`: `((rdi|1) ^ 1) & 1`. Low bit of `(rdi|1)` is 1, so `^1 & 1 = 0`. → always `0`.

Therefore `index = (0 + 2*1) & 3 = 2`, so the only function ever called is `0x401196` (the other three table entries are decoys). Constant-folding the predicates collapses the maze to a single live transform.

### Step 3: Invert the per-byte check

`0x401196(dil=input[i], esi=i)` computes:

```
cl  = 3*i (8-bit)
dil = ROL8(input[i], 3*i)
eax = 5*i - 0x62
edi = dil ^ (eax & 0xff)
esi = i ^ 0x2c
al  = (esi + edi) & 0xff
al  ^= FLAG_KEY[i]
```

For `ebp == 0` we need `al == 0`, i.e. `(esi + dil) == FLAG_KEY[i]`. Solving for `input[i]`:

```
dil = (FLAG_KEY[i] - (i ^ 0x2c)) ^ ((5*i - 0x62) & 0xff)     (mod 256)
input[i] = ROR8(dil, 3*i)
```

Reading `FLAG_KEY[0:0x22]` from the file (virtual `0x4020a0` → file offset via `PT_LOAD`) and applying the inverse over the required 34-byte length yields the flag.

```python
#!/usr/bin/env python3
import struct

with open("branchfog", "rb") as f:
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
        FLAG_KEY = data[p_off + (target - p_vaddr): p_off + (target - p_vaddr) + 0x22]
        break

MASK8 = 0xff
def ror8(b, n):
    n %= 8
    return ((b >> n) | (b << (8 - n))) & MASK8

flag = bytearray()
for i in range(0x22):
    esi = (i ^ 0x2c) & MASK8
    eax = (5*i - 0x62) & MASK8
    dil = ((FLAG_KEY[i] - esi) ^ eax) & MASK8
    flag.append(ror8(dil, (3*i) & 7))

print(flag.decode())
```

### Step 4: Confirm

```
$ printf "cyberstrike{0p4qu3_f0g_dead_paths}\n" | ./branchfog
BranchFog v1.0
Enter password: Correct! Submit your input as the flag.
```

## Flag

```
cyberstrike{0p4qu3_f0g_dead_paths}
```
