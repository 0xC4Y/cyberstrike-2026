---
title: "Vault-X v2: Fragmented Trust"
ctf: "CyberStrike"
date: 2026-07-10
category: reverse
difficulty: insane
points: 600
flag_format: "cyberstrike{...}"
author: "retr0"
---

# Vault-X v2: Fragmented Trust

## Summary

A stripped x86-64 ELF with anti-debug (`ptrace`), a multi-stage transformation pipeline (LCG table generation → in-place XOR/swap/ROL transform → hash), and a decoy flag string in `.rodata`. The correct 16-byte input is an LCG-generated key table. The real flag is decrypted at runtime using the same LCG table as an XOR key — the static string in the binary is a deliberate decoy.

## Solution

### Step 1: Identify the decoy and the real flag mechanism

`strings` reveals: `cyberstrike{v4ul7_x_v2_un7rust4bl3_fr4gm3n7}` — but this is a **decoy** planted in `.rodata`. Disassembly shows the real flag is computed at runtime:

1. Generate a 16-byte LCG table (the "expected" target)
2. Transform the LCG table in-place (XOR/swap/ROL)
3. Hash the transformed table → expected output at `rsp+0x20`
4. Transform user input with the same function
5. Hash the transformed input → result at `rsp+0x30`
6. `memcmp(rsp+0x30, rsp+0x20, 16)` — both must match
7. On success: generate a 16-byte key (same LCG), decrypt 41 bytes from `0x402030` using `flag[i] = enc[i] ^ key[i & 0xf] ^ 0x55`

Since both the input and the LCG table go through the same transform and hash, providing input = LCG table makes them match.

### Step 2: Compute the LCG table and decrypt the flag

```python
#!/usr/bin/env python3
"""Vault-X v2 — LCG key recovery and flag decryption (no binary execution needed)."""
import struct

with open('vault2', 'rb') as f:
    elf = f.read()

# Parse ELF to read .rodata
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

# LCG parameters from disassembly (functions 0x401460 and 0x401500)
# seed=0xc0ffee42, mul=0x19660d, add=0x3c6ef35f
# table[i] = ((seed >> 16) ^ (0xa5 + i*3)) & 0xFF
seed = 0xc0ffee42
lcg_table = []
for i in range(16):
    seed = (seed * 0x19660d + 0x3c6ef35f) & 0xFFFFFFFF
    byte = ((seed >> 16) ^ (0xa5 + i * 3)) & 0xFF
    lcg_table.append(byte)

key = bytes(lcg_table)
print(f"Key (16 bytes): {key.hex()}")

# Decrypt flag: enc at 0x402030 (41 bytes), flag[i] = enc[i] ^ key[i & 0xf] ^ 0x55
enc_flag = read_vaddr(0x402030, 0x29)
flag = bytes([enc_flag[i] ^ key[i & 0xf] ^ 0x55 for i in range(0x29)]).rstrip(b'\x00')
print(f"Flag: {flag.decode()}")
```

### Step 3: Verify against the live binary

```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('6bfc48b0e8546593ce564dde0172a34d') + b'\n')" | ./vault2
# === Vault-X v2: Fragmented Trust ===
# [Vault-X v2] Enter key: [+] Flag: cyberstrike{v4ul7_x_v2_7rus7_fr4grn3n73d}
```

## Flag

```
cyberstrike{v4ul7_x_v2_7rus7_fr4grn3n73d}
```

## Notes

- **Decoy flag**: The string `cyberstrike{v4ul7_x_v2_un7rust4bl3_fr4gm3n7}` in `.rodata` is a decoy. The real flag is encrypted at `0x402030` and only decrypted on successful key validation. Many misleading strings (`auth_init_sequence_v2`, `checksum_mismatch_detected`, `entropy_pool_exhausted`, etc.) are planted to waste analyst time.
- **Anti-debug**: `ptrace(PTRACE_TRACEME, 0, 1, 0)` at `0x401360` (called from main). Returns `-1` if a debugger is attached → `exit(1)`. Bypass with `LD_PRELOAD` or patch.
- **Input method**: `read(0, buf, 16)` reads exactly 16 raw bytes (like Vault-X v1). The key contains non-printable bytes, so it must be piped, not typed.
- **Transformation pipeline**:
  - **LCG table generation** (`0x401500`/`0x401460`): Uses an LCG with seed `0xc0ffee42`, multiplier `0x19660d`, addend `0x3c6ef35f`. Each byte: `((state >> 16) ^ (0xa5 + i*3)) & 0xFF`.
  - **In-place transform** (`0x4013f0`): For each byte: XOR with evolving key (start `0xa5`, step `+7`), add counter (start `0`, step `+3`), swap with position `(0xb + 5*i) & 0xf`, XOR with second evolving key (start `0`, step `+0xd`), ROL 1.
  - **Hash** (`0x4014a0`): Uses a TEA-like constant `0x9e3779b9` to fold each byte into an accumulator, then runs the LCG again to produce 16 output bytes.
- **Key insight**: Both the user input and the LCG table go through the same transform and hash. Providing input = LCG table makes the hash outputs match. The flag is then decrypted using the same LCG table as an XOR key, so computing the LCG table statically gives both the input and the decryption key.
