# PackRat — Writeup

**Category:** Reversing
**Difficulty:** Hard
**Tags:** packer, rle, runtime-unpack
**Flag:** `cyberstrike{p4ck3d_unp4ck_at_runt1m3}`

## Overview

`packrat` is a stripped x86-64 ELF whose real password-check logic never
appears as static code in the binary. Instead, `main()` contains a small
"packer stub" that, at runtime:

1. XOR-decrypts a blob sitting in `.data` using a SplitMix64-style
   keystream with a **hardcoded** seed (not password-derived, unlike some
   sibling challenges).
2. RLE-decompresses the decrypted blob into a freshly `mmap`'d `RWX`
   buffer.
3. `call`s into that buffer, passing the user's input pointer as the
   first argument.

A disassembler only ever sees the unpacker and an opaque data blob — the
actual validator has to be reconstructed by reproducing these two stages
offline.

## Step 1 — Recon

```
file packrat        # ELF 64-bit LSB executable, x86-64, stripped
readelf -S packrat   # .data is unusually large: 0x1020 bytes
```

`main` (at `0x4010b0`) reads a line via `fgets`, and if non-empty jumps to
`0x4010ff`, which is clearly a decrypt loop:

```asm
mov ecx, 0x404060          ; dst cursor
mov edi, 0x4048a2          ; end address (2114 bytes total)
movabs rdx, 0xc0da697980a426a0   ; fixed 64-bit seed
movabs rsi, 0x2545f4914f6cdd1d   ; SplitMix64 multiplier
; loop: mix rdx via shifts/xors, multiply, shift 33, xor into *rcx, rcx++
```

This decrypts a 2114-byte blob **in place** at `0x404060..0x4048a2`.
Immediately after, another loop walks the *decrypted* bytes two at a time
as `(count, value)` pairs and expands them into an `mmap`'d 0x1000-byte
buffer — a classic RLE decoder. Once the buffer is filled, the code does:

```asm
mov  rdi, rsp      ; pointer to the user's raw input
call rbx            ; rbx = the mmap'd, now-populated buffer
```

and checks the returned `eax` for success/failure. That `call rbx` is the
whole ballgame: everything interesting happens inside code that exists
only in memory at runtime.

## Step 2 — Reproducing the XOR keystream

The mixing function matches a **custom SplitMix64 variant** (non-standard
shift amounts: 12 / 25 / 27, final multiplier `0x2545f4914f6cdd1d`,
final shift 33) with a fixed embedded seed — no dependence on user input
or on the binary's own bytes this time, so it's fully reproducible offline
without running the target:

```python
state = 0xc0da697980a426a0
for i in range(len(ciphertext)):
    t1 = state >> 12
    t2 = t1 ^ state
    t3 = (t2 << 25) & MASK64
    t4 = t2 ^ t3
    t5 = t4 >> 27
    t6 = t5 ^ t4
    keystream_byte = ((t6 * 0x2545f4914f6cdd1d) >> 33) & 0xff
    plaintext[i] = keystream_byte ^ ciphertext[i]
    state = t6
```

Decrypting the 2114-byte blob at `0x404060` yields a stream that is
visibly structured as `(count, value)` byte pairs — mostly `01 xx`
(literal single bytes), confirming the RLE hypothesis.

## Step 3 — RLE expansion

The unpack loop reads pairs `(count, value)` starting two bytes *before*
the decrypted region (`0x40405e`, which conveniently holds `00 00` —
a no-op first pair) and writes `value` repeated `count` times into the
`mmap`'d buffer, stopping at 0x1000 bytes total or after consuming up to
0x840 bytes of pair-table. Reproducing this in Python:

```python
buf = bytearray()
i = 0
while i + 1 < len(plaintext) and i < 0x840:
    count, val = plaintext[i], plaintext[i+1]
    i += 2
    buf.extend([val] * count)
```

This produces **1066 bytes of valid x86-64 machine code** — the real
validator, previously invisible to any static disassembler.

## Step 4 — Disassembling the unpacked validator

```
objdump -D -b binary -m i386:x86-64 -M intel unpacked.bin
```

The recovered function:

- Checks the input length is exactly **37 bytes** (`cmp ecx, 0x25`).
- For each character `input[i]`, applies a small per-index affine
  transform: `(c ± k1) ^ k2`, using a *different* `k1`/`k2` pair at every
  index (no repeating XOR key — each byte position is individually
  obfuscated).
- Several of these intermediate per-character results are **spilled to
  the stack** and then **reloaded and passed through a second identical
  transform** before being folded into the final result — a two-stage
  pass that isn't obvious from a linear read of the disassembly and has
  to be tracked with real data-flow, not by eyeballing.
- All 37 per-character results are combined with a long chain of `or`
  instructions into a single accumulator.
- The final comparison only inspects the **low byte** (`or al, bl` /
  `sete dl`) of that accumulator — meaning every one of the 37
  per-character terms must independently equal zero **modulo 256**, not
  as full 32-bit values (an easy point to get wrong, since most terms
  *do* also hash to non-zero at the 32-bit level even when they're
  correct at the byte level that actually gets checked).

## Step 5 — Recovering the password

Rather than hand-tracing 37 register chains (very error-prone — the
compiler freely reuses `ebx`/`r14`/`r15`/etc. as scratch across unrelated
character indices), I wrote a small symbolic interpreter over the
disassembly: each register/stack slot holds either a concrete value or a
pipeline `(index, f)` where `f` composes the `add`/`sub`/`xor`/truncate
operations applied so far to `input[index]`. Every time an `or` folds a
pipeline into the accumulator, its `(index, f)` is recorded as a
constraint `f(c) ≡ 0 (mod 256)`.

With all 37 constraints collected, each is solved independently by
brute-forcing `c` over `0..255` (trivial — 37 × 256 checks):

```python
for idx in range(37):
    f = constraints[idx]
    candidates = [c for c in range(256) if f(c) & 0xff == 0]
    # exactly one match per index
```

Every index resolved to exactly one printable ASCII character:

```
cyberstrike{p4ck3d_unp4ck_at_runt1m3}
```

## Verification

```
$ echo "cyberstrike{p4ck3d_unp4ck_at_runt1m3}" | ./packrat
PackRat v1.0
Enter password: Correct! Submit your input as the flag.
```

## Flag

```
cyberstrike{p4ck3d_unp4ck_at_runt1m3}
```

## Takeaways

- When a binary `mmap`s `RWX` memory, decrypts/decompresses into it, and
  jumps in, static disassembly of the *file* will never show the real
  logic — either reproduce the unpacking algorithm offline (as done
  here) or dump the buffer at runtime (e.g. with a debugger breakpoint
  right after the `call rbx`/before it, or an LD_PRELOAD hook on `mmap`).
- Packing is orthogonal to obfuscation: once unpacked, this challenge
  still had a fairly involved per-character check, including a sneaky
  two-stage stack round-trip that changes the required plaintext if
  missed.
- Always check *which bits* actually feed the final `sete`/branch. A
  32-bit accumulator OR'd from many terms can still boil down to a
  narrower (here 8-bit) comparison at the end, which changes which
  solutions are valid.
- For long chains of register-reused arithmetic, a short symbolic
  data-flow interpreter is far more reliable than manual tracing —
  it turned a spaghetti of `r8d`–`r15d` reuse into 37 clean, independent
  equations.
