# CryptFold — Writeup

**Category:** Reversing
**Difficulty:** Insane
**Tags:** layered mba, self-decrypt, indirect-dispatch
**Flag:** `cyberstrike{cr9pt_f0ld_l4y3rs_st4ck3d}`

## Overview

`cryptfold` is a small stripped x86-64 ELF binary that reads a password from
stdin and tells you whether it's correct. The challenge stacks four
independent defenses so that defeating any one of them alone still leaves
you with nothing:

1. An **indirect dispatch table** with decoy functions hiding which check
   actually runs.
2. A **mixed boolean-arithmetic (MBA)** per-character transform.
3. A **runtime-decrypted target table**, keyed by a hash of the binary
   itself (self-hash-keyed decryption).
4. **Zero plaintext strings** — no cleartext password or flag exists
   anywhere in the file; everything is derived and compared byte-by-byte.

Static analysis alone (`objdump`, `readelf`) was enough to fully recover
the algorithm — no debugger/emulation was required, since the binary is
tiny (`.text` is only ~0x42f bytes).

## Step 1 — Recon

```
file cryptfold
# ELF 64-bit LSB executable, x86-64, stripped

readelf -S cryptfold
```

Interesting sections jumped out immediately:

- `.note.ai_warn` — contains a plaintext note aimed at automated solvers,
  explicitly stating: *"targets are encrypted with a key derived from
  this note's hash ... the real check is selected by indirect dispatch
  among decoys ... Editing this note changes the key -> INVALID flag."*
  This is **not a joke** — it's load-bearing. The note's raw bytes are
  literally hashed at runtime to derive the decryption key, so an
  automated patcher that strips or "cleans up" this note breaks its own
  attempt.
- `.note.decoy` — a second note section, deliberately named to bait
  solvers into wasting time on it. It's never referenced by the program.

## Step 2 — The self-hash-keyed decryption

At `0x401389`, the binary computes a 64-bit FNV-1a hash over the raw 228
bytes of the `.note.ai_warn` section (file/vaddr `0x400380`..`0x400380+0xe4`):

```
rax = 0xcbf29ce484222325        ; FNV-1a offset basis
for each byte b in note[0:0xe4]:
    rax ^= b
    rax *= 0x100000001b3        ; FNV-1a prime
rax ^= 0x6e2ab96725106e21       ; extra whitening constant
```

The result seeds a **SplitMix64-style** keystream generator (custom shift
constants: 12 / 25 / 27, final multiply by `0x2545f4914f6cdd1d`, shift 33):

```
state = seed
for i in range(38):
    state ^= state >> 12
    t = (state << 25) ^ state
    state = (t >> 27) ^ t
    x = (state * 0x2545f4914f6cdd1d) >> 33
    keystream_byte = x & 0xff
    plaintext[i] = keystream_byte ^ ciphertext[i]
```

`ciphertext` is a 38-byte blob stored in `.rodata` at `0x4020a0`. Decrypting
it does **not** yield a readable string — it yields a table of 38
*expected transformed byte values*, one per password character. That threw
me off initially (I expected ASCII and got garbage), until I found how the
table is actually consumed.

## Step 3 — The indirect dispatch decoy

The password length is checked first: it must be **exactly 38 bytes**
(`cmp rbx, 0x26`), matching the decrypted table's length.

Then, for each character `input[idx]`, the binary computes a selector:

```
selector = ((idx - 1) * idx) & 1
call [dispatch_table + selector*8]
```

`dispatch_table[0] = 0x401175` (the real transform)
`dispatch_table[1] = 0x4011ac` (a decoy — never actually reached)

The trick: `(idx-1) * idx` is always a product of two **consecutive
integers**, so it's always even. `selector` is therefore always `0` —
the "dispatch" is 100% static, but disguised as data-dependent to bait
anyone reading dynamically or skimming the binary into thinking both
paths matter. There are also a few extra unreferenced helper functions
(`0x401166`, `0x401170`, `0x4011a6`, `0x4011b5`) that exist purely as
red herrings and are never called from the real path.

## Step 4 — The MBA transform

The real per-character function (`0x401175`), given `(c = input[idx],
idx)`:

```
t      = c ^ (idx*9 + 0x4d)
r      = rol8(t, idx*2 + 1)
a2     = idx*idx
b2     = a2 ^ 0x63
mix    = (r ^ b2) + 2*(r & b2)     ; MBA identity: (x^y) + 2*(x&y) == x+y
a3     = a2 * idx                   ; = idx^3
result = mix ^ a3
```

The `(x^y) + 2*(x&y)` pattern is the classic **mixed boolean-arithmetic**
identity for integer addition (`x + y`), used here to obscure a plain sum
behind bitwise ops — a hallmark MBA obfuscation trick. I initially missed
that the cubic term (`idx*idx*idx`) is computed via **two** `imul`
instructions in sequence (`ebp = idx*idx`, then later `ebp = ebp*idx`
again reusing the same register) — mis-tracking that second multiply
produced a wrong "expected" table and non-printable garbage output on my
first pass. Once corrected, `funcA` turned out to be a clean bijection
over all 256 byte values per index, so it can be inverted by brute force
in $O(256 \times 38)$ time.

## Step 5 — Recovering the password

With `funcA` correctly modeled, invert it against each decrypted target
byte:

```python
for idx in range(38):
    target = table[idx]
    match  = [c for c in range(256) if funcA(c, idx) == target]
    # exactly one match per index
```

Every index resolved to exactly one printable ASCII character, giving:

```
cyberstrike{cr9pt_f0ld_l4y3rs_st4ck3d}
```

## Verification

```
$ echo "cyberstrike{cr9pt_f0ld_l4y3rs_st4ck3d}" | ./cryptfold
CryptFold v1.0
Enter password: Correct! Submit your input as the flag.
```

## Flag

```
cyberstrike{cr9pt_f0ld_l4y3rs_st4ck3d}
```

## Takeaways

- Read every section, including ones that look like junk (`.note.*`) —
  here the "warning to automated solvers" note was itself the decryption
  key material, not commentary.
- "Indirect dispatch" doesn't always mean the target is actually
  variable at runtime — check whether the selector expression can ever
  take more than one value before spending time RE-ing every branch.
- When an MBA expression like `(x^y) + 2*(x&y)` shows up, recognize it as
  disguised addition rather than trying to simplify it bit-by-bit.
- Re-read multi-instruction arithmetic sequences carefully for reused
  registers (e.g. two `imul` instructions on the same accumulator) —
  it's an easy place to misread `x²` for `x³`.
