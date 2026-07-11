---
title: "SelfMorph"
ctf: "CyberStrike"
date: 2026-07-10
category: reverse
difficulty: very-hard
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# SelfMorph

## Summary

A stripped x86-64 ELF stores its password validator as encrypted data in `.data`, decrypted at runtime via an Xorshift64 PRNG into an RWX page, then re-encrypted after use. Static analysis yields only garbage. A decoy `.note.decoy` section and reversed success/failure message paths add misdirection. Replicating the PRNG decryption reveals a 35-byte checker with per-position ROL/ROR/XOR/ADD transforms, each inverted to recover the flag.

## Solution

### Step 1: Identify the self-modifying code mechanism

The main function (`0x4010b0`) does:

1. `fgets` input (up to 128 bytes), strips newline
2. `sysconf(_SC_PAGESIZE)` → compute page-aligned address for `0x406400`
3. `mprotect(page, 0x406400 - page_base, PROT_READ|PROT_WRITE|PROT_EXEC)` — make `.data` RWX
4. `call 0x401270` — **decrypt** the 1024-byte blob at `0x406000` using Xorshift64
5. `call 0x406000` — **execute the decrypted blob as code** (the validator)
6. `call 0x401270` again — **re-encrypt** (XOR is self-inverse)
7. If validator returned 0 → print "Correct! Submit your input as the flag."
8. If validator returned non-zero → call `assemble_flag` which prints "Wrong. computed token: ..."

The `.note.decoy` section contains fake "BUILD METADATA" about `derive_flag()`, `FLAG_KEY[]`, and `verify_checksum()` — none of which exist in the actual code.

### Step 2: Replicate the Xorshift64 decryption statically

The decrypt function at `0x401270` uses an Xorshift64\* PRNG:

- **Seed**: `0x5ec897ab4b1c0485`
- **Multiplier**: `0x2545f4914f6cdd1d`
- Per byte: `state ^= state >> 12; state ^= state << 25; state ^= state >> 27; prng_byte = ((state * multiplier) >> 33) & 0xFF; blob[i] ^= prng_byte`

```python
import struct

with open('selfmorph', 'rb') as f:
    elf = f.read()

# Parse ELF to find .data section
e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

def read_vaddr(vaddr, size):
    for i in range(e_shnum):
        sh = e_shoff + i * e_shentsize
        sh_addr = struct.unpack_from('<Q', elf, sh + 0x10)[0]
        sh_offset = struct.unpack_from('<Q', elf, sh + 0x18)[0]
        sh_size = struct.unpack_from('<Q', elf, sh + 0x20)[0]
        if sh_addr <= vaddr < sh_addr + sh_size:
            return elf[sh_offset + (vaddr - sh_addr):][:size]
    return None

# Decrypt the 1024-byte blob at 0x406000
blob = bytearray(read_vaddr(0x406000, 0x400))
state = 0x5ec897ab4b1c0485
multiplier = 0x2545f4914f6cdd1d

for i in range(0x400):
    state ^= (state >> 12)
    state &= 0xFFFFFFFFFFFFFFFF
    state ^= (state << 25)
    state &= 0xFFFFFFFFFFFFFFFF
    state ^= (state >> 27)
    state &= 0xFFFFFFFFFFFFFFFF
    prng_byte = ((state * multiplier) >> 33) & 0xFF
    blob[i] ^= prng_byte

# Disassemble decrypted blob to see the validator
# objdump -D -b binary -m i386:x86-64 decrypted_blob.bin
```

### Step 3: Reverse the per-position transforms in the decrypted validator

The decrypted validator checks a 35-byte input. Each byte position has a unique transform pattern that must produce 0. The patterns cycle through ROL/ROR by `(position_in_group + 1)` bits, combined with ADD or SUB and double XOR.

```python
def rol8(v, n): return ((v << n) | (v >> (8 - n))) & 0xFF
def ror8(v, n): return ((v >> n) | (v << (8 - n))) & 0xFF

# Each check: ((input[offset] ^ c1) ROL/ROR n) +/- c2) ^ c3 == 0
# Format: (offset, c1, rotate_type, rotate_n, op, c2, c3)
checks = [
    (0x00, 0x63, 'none', 0, 'none', 0, 0),
    (0x08, 0x93, 'none', 0, 'add', 0x40, 0x3a),
    (0x10, 0x5f, 'none', 0, 'none', 0, 0),
    (0x18, 0x03, 'none', 0, 'add', 0x40, 0xa4),
    (0x20, 0x31, 'none', 0, 'none', 0, 0),
    (0x01, 0x62, 'rol', 1, 'add', 0x01, 0x37),
    (0x02, 0x69, 'rol', 2, 'add', 0x04, 0x30),
    (0x03, 0x70, 'rol', 3, 'add', 0x09, 0xb1),
    (0x04, 0x77, 'rol', 4, 'add', 0x10, 0x60),
    (0x05, 0x7e, 'ror', 3, 'add', 0x19, 0xba),
    (0x06, 0x85, 'ror', 2, 'add', 0x24, 0xa0),
    (0x07, 0x8c, 'ror', 1, 'add', 0x31, 0xb0),
    (0x09, 0x9a, 'rol', 1, 'add', 0x51, 0x34),
    (0x0a, 0xa1, 'rol', 2, 'add', 0x64, 0x77),
    (0x0b, 0xa8, 'rol', 3, 'add', 0x79, 0x17),
    (0x0c, 0xaf, 'rol', 4, 'sub', 0x70, 0x5d),
    (0x0d, 0xb6, 'ror', 3, 'sub', 0x57, 0x59),
    (0x0e, 0xbd, 'ror', 2, 'sub', 0x3c, 0x38),
    (0x0f, 0xc4, 'ror', 1, 'sub', 0x1f, 0x32),
    (0x11, 0xd2, 'rol', 1, 'add', 0x21, 0xa0),
    (0x12, 0xd9, 'rol', 2, 'add', 0x44, 0xeb),
    (0x13, 0xe0, 'rol', 3, 'add', 0x69, 0xfd),
    (0x14, 0xe7, 'rol', 4, 'sub', 0x70, 0x09),
    (0x15, 0xee, 'ror', 3, 'sub', 0x47, 0x89),
    (0x16, 0xf5, 'ror', 2, 'sub', 0x1c, 0x15),
    (0x17, 0xfc, 'ror', 1, 'add', 0x11, 0x5a),
    (0x19, 0x0a, 'rol', 1, 'add', 0x71, 0x1b),
    (0x1a, 0x11, 'rol', 2, 'sub', 0x5c, 0x6d),
    (0x1b, 0x18, 'rol', 3, 'sub', 0x27, 0x1a),
    (0x1c, 0x1f, 'rol', 4, 'add', 0x10, 0xc7),
    (0x1d, 0x26, 'ror', 3, 'add', 0x49, 0xeb),
    (0x1e, 0x2d, 'ror', 2, 'sub', 0x7c, 0x20),
    (0x1f, 0x34, 'ror', 1, 'sub', 0x3f, 0x62),
    (0x21, 0x42, 'rol', 1, 'add', 0x41, 0x99),
    (0x22, 0x49, 'rol', 2, 'sub', 0x7c, 0x54),
]

flag = [0] * 35
for offset, c1, rtype, rn, op, c2, c3 in checks:
    if rtype == 'none' and op == 'none':
        flag[offset] = c1
    elif rtype == 'none' and op == 'add':
        flag[offset] = ((c3 - c2) & 0xFF) ^ c1
    elif rtype == 'rol' and op == 'add':
        flag[offset] = ror8((c3 - c2) & 0xFF, rn) ^ c1
    elif rtype == 'ror' and op == 'add':
        flag[offset] = rol8((c3 - c2) & 0xFF, rn) ^ c1
    elif rtype == 'rol' and op == 'sub':
        flag[offset] = ror8((c3 + c2) & 0xFF, rn) ^ c1
    elif rtype == 'ror' and op == 'sub':
        flag[offset] = rol8((c3 + c2) & 0xFF, rn) ^ c1

print(bytes(flag).decode())
```

### Step 4: Verify against the live binary

```bash
echo 'cyberstrike{s3lf_m0rph1ng_c0d3_w1n}' | ./selfmorph
# SelfMorph v1.0
# Enter password: Correct! Submit your input as the flag.
```

## Flag

```
cyberstrike{s3lf_m0rph1ng_c0d3_w1n}
```

## Notes

- **Self-modifying code**: The validator lives encrypted in `.data` at `0x406000` (1024 bytes). At runtime, `mprotect` makes the page RWX, an Xorshift64\* PRNG decrypts it in-place, the decrypted code is called as a function, then the same PRNG pass re-encrypts it. A static dump of the file's data sections yields only encrypted garbage.
- **Xorshift64\* parameters**: Seed `0x5ec897ab4b1c0485`, multiplier `0x2545f4914f6cdd1d`. The PRNG output byte is `((state * multiplier) >> 33) & 0xFF`. Replicating this in Python produces the correct decryption without needing to run the binary under GDB.
- **Decoy `.note.decoy`**: Contains fake "BUILD METADATA" about `derive_flag()`, `FLAG_KEY[]`, `verify_checksum()`, and `libflaggen` — none of which exist in the code. Designed to mislead AI/static analysis.
- **Reversed message paths**: The "Wrong. computed token: %s" message is printed by `assemble_flag()` on the **failure** path (when the validator returns non-zero), not on success. The "Correct!" message is on the actual success path (validator returns 0).
- **Validator structure**: 35 bytes checked, each with a unique transform: `XOR c1 → ROL/ROR n → ADD/SUB c2 → XOR c3 → must equal 0`. Positions 0x00, 0x08, 0x10, 0x18, 0x20 have simpler checks (no rotation). The rotation amount cycles 1-4 based on position within each 8-byte group. All 35 transforms invert cleanly to recover the flag.
- **GDB alternative**: Per the challenge hint, setting a breakpoint at `0x40112d` (right after the first decrypt call) and examining memory at `0x406000` would reveal the decrypted validator code without needing to replicate the PRNG.
