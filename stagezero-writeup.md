# StageZero — Writeup

**Category:** Reversing / Packer / Runtime-Decrypt
**Points:** 450
**Difficulty:** Very Hard
**Flag:** `cyberstrike{st4g3_z3r0_dr0pp3r_run}`

## Challenge Description

> A loader that carries its real validator as an encrypted second stage.
> Stage 1 decrypts Stage 2 into an executable page and jumps to it; the
> check exists only at runtime. There is no single pasteable unit — you
> must unpack the dropper.
>
> The second stage never touches disk in cleartext and is re-encrypted
> after use, so a memory dump taken at the wrong moment is also blank.
> Catch it in the window between decrypt and re-encrypt, or reproduce the
> keystream offline.

## Initial Recon

```
$ file stagezero
stagezero: ELF 64-bit LSB executable, x86-64, ... stripped
```

`strings` shows the same "BUILD METADATA... FLAG_KEY[]... verify_checksum()"
decoy text seen in other challenges in this series — a bait comment aimed at
solvers who try to patch a checksum rather than actually reverse the
program. It also shows the runtime UI text:

```
StageZero v1.0
Enter password:
Correct! Submit your input as the flag.
Wrong. computed token: %s
```

Imported functions include `mprotect`, which is the giveaway for the
"encrypted second stage" design: the loader is going to `mprotect()` a
region of its own memory executable, decrypt into it, run it, then encrypt
it back.

## Stage 1 — The Dropper

Disassembling `.text` (the only non-stripped, always-visible code) shows
`main`'s logic:

1. Print the banner + `Enter password: `, read up to 0x80 bytes with
   `fgets`, strip the trailing newline.
2. Compute the page-aligned base of the buffer at `0x406800` and call
   `mprotect(addr, size, PROT_READ|PROT_WRITE|PROT_EXEC)` to make a region
   of `.data`/`.bss` executable.
3. Call a local function at `0x401270` — this **decrypts** 0x800 (2048)
   bytes at `0x406000..0x406800` in place.
4. `mov rdi, rsp; call 0x406000` — **call directly into the now-decrypted
   memory as a function**, passing a pointer to the password buffer.
5. Call `0x401270` again — because the cipher is a symmetric stream cipher
   (XOR with a keystream), calling the *same* decrypt routine a second time
   with the same deterministic keystream **re-encrypts** the region back
   to its original ciphertext. This is the "re-encrypted after use" step
   from the description — a static dump of the binary, or a memory dump
   taken outside this narrow window, only ever shows ciphertext.
6. Check the return value from the Stage-2 call:
   - **non-zero → correct password** → print `Correct! Submit your input
     as the flag.`
   - **zero → wrong password** → call a decoy function that fills a buffer
     with a Numerical-Recipes-LCG pseudo-random string (seeded from a fixed
     constant `0x1337beef`, independent of the actual password) and prints
     it as `Wrong. computed token: %s`. This "computed token" is a red
     herring — it's not derived from the input or from any hash chain, it's
     just noise to bait an automated solver into treating it as the target.

## Stage 2 — The Encrypted Validator

### Recovering the keystream

Function `0x401270` implements **xorshift64\*** — a standard, recognizable
PRNG:

```c
x ^= x >> 12;
x ^= x << 25;
x ^= x >> 27;
output_byte = (x * 0x2545F4914F6CDD1D) >> 33;   // low byte used
```

seeded with the fixed 64-bit constant `0x8d00c756af47264f`, generating one
keystream byte per iteration and XOR-ing it into successive bytes of
`[0x406000, 0x406800)`. Because the seed and multiplier are hard-coded
constants baked into the binary, the keystream is **fully reproducible
offline** without ever running the program — no need to catch the "decrypt
window" live at all.

`0x406000` falls inside `.data` (`PROGBITS`, file offset `0x4000`, so
`0x406000` is at file offset `0x5000`). Extracting those 2048 bytes and
XOR-ing them with a Python re-implementation of xorshift64\* immediately
produces valid x86-64 machine code (`push r15; push r14; push r13; push
r12; push rbp; push rbx; ...` — a normal function prologue).

### Reversing the validator logic

The decrypted Stage 2 is a `validate(const char *password)` function. It:

1. Requires the input to be **exactly 35 characters** (`cmp ecx, 0x23`, i.e.
   0x23 = 35).
2. For **each of the 35 character positions independently**, applies a
   two-stage transform:
   - **Stage A:** rotate the input byte (`rol`/`ror` by 1–4 bits, varying
     per position; every 8th position — 0, 8, 16, 24, 32 — skips the
     rotate), add `0x3b`, then XOR with a per-position constant.
   - **Stage B:** subtract the position index (mostly) from the Stage-A
     result, then XOR with a second per-position constant.
3. **OR-accumulates** all 35 per-position results together. Because OR of
   unsigned values is zero *only* if every operand is zero, and the OR is
   ultimately tested via a single-byte `or dil, al; sete dl`, success
   requires **every position's two-stage result to independently equal
   zero (mod 256)**.

Critically, each position's check is **fully independent of the others** —
there's no cross-position dependency (unlike a running hash/CRC), so each
of the 35 target characters can be recovered by brute-forcing 0–255 against
that position's own tiny transform and requiring the result to be `0`.

### Solving

A short Python script replays each position's exact instruction sequence
(rotate → add → xor → subtract-index → xor) for all 256 byte values and
keeps whichever byte drives that position's result to zero. Every one of
the 35 positions has a unique, printable-ASCII solution:

```
pos  0: c        pos 12: s        pos 24: r
pos  1: y        pos 13: t        pos 25: 0
pos  2: b        pos 14: 4        pos 26: p
pos  3: e        pos 15: g        pos 27: p
pos  4: r        pos 16: 3        pos 28: 3
pos  5: s        pos 17: _        pos 29: r
pos  6: t        pos 18: z        pos 30: _
pos  7: r        pos 19: 3        pos 31: r
pos  8: i        pos 20: r        pos 32: u
pos  9: k        pos 21: 0        pos 33: n
pos 10: e        pos 22: _        pos 34: }
pos 11: {         pos 23: d
```

Concatenated, this spells the password (and, per the challenge's own
runtime message, "submit your input as the flag") directly:

```
cyberstrike{st4g3_z3r0_dr0pp3r_run}
```

### Verification

```
$ echo "cyberstrike{st4g3_z3r0_dr0pp3r_run}" | ./stagezero
StageZero v1.0
Enter password: Correct! Submit your input as the flag.
```

Negative control, confirming the "computed token" really is a
non-informative decoy on any wrong guess:

```
$ echo "cyberstrike{wrong_password_test_case}" | ./stagezero
StageZero v1.0
Enter password: Wrong. computed token: cyberstrike{lncap4jn9ui6al3fhn4e}
```

## Flag

```
cyberstrike{st4g3_z3r0_dr0pp3r_run}
```

## Takeaways

- **A self-decrypting/self-encrypting stage doesn't require live memory
  forensics if the keystream generator is deterministic.** Spotting
  `mprotect` + a two-call symmetric-cipher pattern (decrypt, run, re-encrypt
  with the same routine) is the signal that the "second stage" can be
  recovered entirely statically: extract the ciphertext bytes from the file,
  reimplement the PRNG, XOR offline.
- **xorshift64\*** is a very recognizable PRNG shape (three shift/XOR steps
  followed by a multiply-and-shift) — spotting it saves having to
  brute-force or symbolically execute the keystream generator.
- **Per-character independent verification loops that funnel into a single
  OR-then-compare-to-zero** are solvable position-by-position, exactly like
  a substitution cipher: brute force each position's tiny 256-value space
  independently instead of trying to search the full 256^35 password space.
- **The printed "computed token" on failure is a deliberate distraction** —
  it's generated from a fixed seed unrelated to the actual input, aimed at
  solvers (particularly automated/LLM-assisted ones) who assume any
  cyberstrike{...}-shaped string printed by the binary must be meaningful.
