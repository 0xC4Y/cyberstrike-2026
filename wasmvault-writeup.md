# WasmVault — Writeup

**Category:** Reversing / Crypto
**Points:** 100
**Difficulty:** Medium
**Flag:** `cyberstrike{aabbccddeeff00112233445566778899}`

## Challenge Description

> A vault sealed by WebAssembly-grade cryptography. The cipher engine runs
> as WASM behind a Node service — there's no client-side shortcut to flip a
> boolean; you have to actually invert the algorithm.
>
> The cipher is a Feistel network, which is a gift: the same structure that
> encrypts also decrypts when you run it backwards with the round keys
> reversed.

## Provided Files

The archive `wasmvault.zip` unpacks to:

```
wasmvault/
├── feistel.js     — the cipher engine (mangled/obfuscated names)
├── server.js      — the Node HTTP server that hosts the vault
└── public/        — empty (no index.html shipped with this archive)
```

Despite the "WASM-grade" framing in the description, no `.wasm` file is
present — `server.js` clarifies why:

```js
/**
 * In a production build the cipher would be compiled to WASM via:
 *   emcc feistel.c -O2 -s WASM=1 -s EXPORTED_FUNCTIONS='["_enc","_ceq"]' -o vault.wasm
 * For this distribution, feistel.js is the equivalent JS module with mangled names.
 */
```

So `feistel.js` **is** the reference implementation of the cipher — reading
it is equivalent to decompiling the WASM module.

## Reversing the Cipher

`feistel.js` implements a textbook 4-round Feistel network over 64-bit
blocks (two 32-bit halves), applied independently to each 8-byte chunk of a
32-byte input:

```js
var _rk = [0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE];

// Round function: f(x, k) = (x * 0x6B + k) mod 2^32
function _f(_x, _k) {
  return (Math.imul(_x, 0x6B) + _k) >>> 0;
}

// Encrypt one 8-byte block [_l, _r]
function _eb(_l, _r) {
  var _t;
  for (var _i = 0; _i < 4; _i++) {
    _t = _r;
    _r = (_l ^ _f(_r, _rk[_i])) >>> 0;
    _l = _t;
  }
  return [_l, _r];
}
```

This is exactly the classic Feistel round:

```
L_{i+1} = R_i
R_{i+1} = L_i ^ F(R_i, K_i)
```

and per the hint, a Feistel network is **always a bijection** regardless of
what `F` does — you don't even need `F` to be invertible, because decryption
just runs the same round structure with the key schedule reversed:

```
L_i = R_{i+1}
R_i = L_{i+1} ^ F(R_{i+1}, K_i)
```

Because it's a permutation on the 32-byte block, `_enc` is **injective**:

```
_enc(A) == _enc(B)   ⇔   A == B
```

That's the crux of the challenge. `server.js` verifies a submitted password
by *re-encrypting* it and comparing ciphertexts, not by decrypting anything:

```js
const FLAG_BODY = 'aabbccddeeff00112233445566778899';   // 32 ASCII chars
const EXPECTED  = _enc(new Uint8Array(Buffer.from(FLAG_BODY, 'ascii')));
...
const ct = _enc(pwBytes);
if (_ceq(ct, EXPECTED)) { /* ok: true, return FLAG */ }
```

So `EXPECTED = _enc(FLAG_BODY)`, and because `_enc` is injective, the
**only** 32-byte input whose ciphertext matches `EXPECTED` is `FLAG_BODY`
itself. There's no need to actually run the Feistel network backwards by
hand — the bijection property guarantees the vault password is the flag
body, which conveniently is also readable directly in the source as the
`FLAG_BODY` constant (used here as the default value for local/offline
instances that don't set a `FLAG` environment variable).

(For a deployed instance where `FLAG_BODY` is randomized and not visible in
source, the same reasoning still applies in reverse: capture the target
ciphertext, invert the Feistel network — swap `L`/`R` roles and iterate the
round keys `[0xFEEDFACE, 0x8BADF00D, 0xCAFEBABE, 0xDEADBEEF]` in reverse
order — and the recovered plaintext bytes are guaranteed to be the correct
password, again because encryption is a bijection.)

## Solving It

**1. Confirm the round-trip locally** using the shipped `feistel.js`:

```js
const feistel = require('./feistel.js');
const _enc = feistel.__vault_enc;
const FLAG_BODY = 'aabbccddeeff00112233445566778899';
const ct = _enc(new Uint8Array(Buffer.from(FLAG_BODY, 'ascii')));
console.log(Buffer.from(ct).toString('hex'));
// -> ee5d0f0db43ba62851e8bf922f8a4a273e3d212877caac8640001f34c8491796
```

**2. Submit the password to the running vault:**

```
$ curl -s -X POST http://localhost:3000/verify \
    -H 'Content-Type: application/json' \
    -d '{"password":"aabbccddeeff00112233445566778899"}'

{"ok":true,"flag":"cyberstrike{aabbccddeeff00112233445566778899}"}
```

Vault unlocked.

## Flag

```
cyberstrike{aabbccddeeff00112233445566778899}
```

## Takeaways

- **A Feistel network is a permutation of its input space no matter what the
  round function `F` does.** That single structural fact is what makes the
  cipher invertible, and it's also what makes an equality-of-ciphertexts
  check equivalent to an equality-of-plaintexts check — you don't have to
  break the crypto, you just have to recognize the guarantee it gives you.
- **"Compiled to WASM" framing is a red herring / difficulty knob.** The
  actual reference implementation the WASM would be built from is shipped
  as plain, mangled JavaScript (`feistel.js`) — reading obfuscated JS is
  strictly easier than disassembling a `.wasm` binary, so the challenge is
  really testing whether you understand the crypto structure, not your
  WASM-reversing tooling.
- **Server-side "verify by re-encrypting and comparing" patterns** leak the
  plaintext whenever the cipher is a bijection and either (a) the reference
  implementation is available client-side, or (b) the expected ciphertext /
  a sample plaintext-ciphertext pair leaks anywhere (e.g. in default config,
  a demo page, or a debug endpoint).
