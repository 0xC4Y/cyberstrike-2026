---
title: "The King's Vault"
ctf: "Unsolved"
date: 2026-07-11
category: reverse
difficulty: hard
points: 600
flag_format: "unknown (not recovered)"
author: "retr0"
status: "UNSOLVED — exhaustive negative results, no flag recovered"
---

# The King's Vault

## Summary

Recovered an authorization token from a locked-archive challenge built around a single
native library (`deriveVaultKey`) and a KVS1 sync-protocol capture. Confirmed key
derivation (32-byte vault key from pcap challenge), confirmed protocol framing, and
parsed every artifact. The flag was not recovered: the vault key does not decrypt
`wrapped_identity` (256 bytes) or the P4 payload (139 bytes) in any standard mode/KDF
combination I could construct.

## Challenge Artifacts (7 files)

| File | Size | Role |
|------|-----:|------|
| `KingVault.apk` | 96 KB | Decoy container. Fake `classes.dex` (132 B) + 200 identical `res/raw/*.txt` + 134 Java stubs + `libkingvault.so` |
| `lib/x86_64/libkingvault.so` | 14112 B | The only meaningful code. Exports `deriveVaultKey` and `kingvault_blob_len` |
| `career_records.dat` | 878 B | `KVREC6` magic + 872 B binary. No parseable inner structure. |
| `kingvault.vlt` | 2498 B | `KVLT` magic + 48 B binary header + inner header `KVLT\|VK18\|v6\|boss` (at offset 64) + 2416 B payload |
| `match_sync.pcapng` | 772 B | KVS1 protocol: 4 messages (type 1 hello, type 2 32-byte challenge, type 4 139-byte data, type 5 sync-complete) |
| `score_archive.db` | 20 KB | SQLite. `vault_metadata` with `wrapped_identity` (256 B), `sync_salt`, `hkdf_salt`, `pbkdf_rounds=180000`, `hkdf_info="kingvault:kvlt-wrap:v6"`, `version_history`, `commentary` ("Salt is never stored where fans expect it." / "Numbers never lie, but byte order does.") |
| `cover.jpg` | 22 KB | JPEG with cricket-themed EXIF: `Make=MRF`, `Model=CoverDrive-18`, `ImageUniqueID=VK-ODI50-183-2011` |
| `crowd.wav` | 48 KB | 8000 Hz mono PCM audio (not examined) |
| `career_manifest.json` | 69 B | `{"profile": "archive", "version": "6.0", "storage": "vault"}` |
| APK assets | — | `assets/media/catalog.json`: `{"albums":18,"posters":50,"sync":"enabled"}`; 200 identical `res/raw/resource_XXX.txt` |

## Ground-Truth Confirmed

### `deriveVaultKey` (full disassembly, 184 bytes, 2 functions total in .so)

Algorithm: `out[i] = input[i % input_len] ^ kingvault_rsa_blob[(7*i) % 311]`, for i=0..31.

`kingvault_rsa_blob` is 311 bytes (0x137), magic `KVRSA5\0\x18` + 303 bytes of data
at the start of `.rodata`. The function is the only real code in the .so and the
only code in the entire delivered artifact set (Java side is all stubs).

### Vault key (from pcap challenge via deriveVaultKey)

Challenge (32 bytes from pcap type-2): `d9b79de473cc4adda67bdc1045eb0b6386ac58e308819a3b3059f0416895977b`

Vault key: `92afbde5e72898870f9990b23366a5bd4d2f0314f078dcb85e747e88ddcb6d5f`

### KVS1 protocol framing (7 bytes header per message)

`KVS1` (4) + type (1) + flags (1) + len (1) + payload(len). Type 4 payload: 139 bytes,
not block-aligned (139 mod 16 = 11). 139 = 12 + 111 + 16 (GCM split) or 16 + 107 + 16
or 32 + 91 + 16.

## Exhaustive Negative Results

### 1. `wrapped_identity` (256 B) in `score_archive.db` — NOT decryptable

Tested against the vault key, reversed vault key, SHA-256 of both:
- **AES-256-CBC** with IVs: `sync_salt`, `hkdf_salt`, `challenge[:16]`, `wi[:16]`, zeros,
  challenge-derived, and every record/vlt/career_records file's first 16 bytes.
- **PBKDF2(vk, salt, 180000, SHA-256)** with salts: `sync_salt`, `hkdf_salt`, challenge,
  `VK-ODI50-183-2011`, all 14 cipher-profile strings, concatenated profiles, all
  `gallery-screen-*` and `poster-fragment-*` strings, "boss"/"kingvault-boss"/
  "KVLT|VK18|v6|boss" and all cross-artifact tokens.
- **PBKDF2 then HKDF** chains with all above as info.
- **AES-256-ECB** with vault key directly.
- **XOR** with vault key repeating (106/256 printable — noise level).

**Zero hits.** No PKCS7 padding validation passes, no meaningful text emerges.

### 2. P4 payload (139 B) from pcap — NOT decryptable

Tested with the vault key, reversed vault key, SHA-256 of both, PBKDF2/HKDF derivations
of both, XOR-derived mixed keys (`SHA256(vk||chal)`, `SHA256(vk||sync_salt)`, etc.):
- **AES-256-GCM** with splits: 12+111+16, 16+107+16, 32+91+16.
- **Nonces**: P4 first 12 bytes, challenge first 12, `sync_salt[:12]`, `hkdf_salt[:12]`, zeros.
- **AADs**: "KVS1\x04", "KVS1", full challenge, P4 first 7 bytes, all session string
  fields (`vk-18-6.0`, `VK18`, `v6`, `6.0`, `boss`, `vk-18`, `gallery-sync`, full session),
  vlt inner header.
- **AES-256-CBC**: ruled out structurally (139 mod 16 = 11).
- **AES-256-CTR**: no readable plaintext.
- **XOR** with vault key, challenge, rsa_blob, and every available constant.

**Zero hits.** MAC verification fails universally.

### 3. Cross-artifact relationships (not found)

- P4 and `kingvault.vlt` share zero byte-level correlation (tested 8/16/32 byte
  windows from both ends of P4 against all of vlt).
- vlt and career_records have no obvious structural relationship.
- The 14 cipher-profile strings ("vaultcipher-profile" etc.) and the vlt header
  cross-reference is real but produces no working decryption.

## Open Threads Not Resolved

1. **KVPLAN5 plan blobs (1438 + 231 + 240 + 223 + 335 bytes of code)**: Extensive
   analysis of these as potential XOR-encoded text or bytecode VM showed no convergent
   decoding. Kasiski analysis at kl=14 was an initial signal but didn't generalize
   across files.

2. **`career_records.dat` (872 B after KVREC6 header)**: Fully dumped, no parseable
   inner structure, no decryption path found with any tested key.

3. **`crowd.wav`**: Not examined. Hint "Salt is never stored where fans expect it"
   could point to audio steganography, but no plan/code examined matches audio extraction.

4. **Type-3 and other protocol types**: Pcap only shows types 1, 2, 4, 5. Other types'
   semantics are unknown from observation.

5. **The 48 bytes at `vlt[14:62]`**: Matches none of the known crypto material
   (vault key, challenge, sync_salt, hkdf_salt, rsa_blob key material). No tested
   derivation produces a working key from it.

6. **`KINGVAULT_BLANK_TEXT` flag/key inside `cover.jpg` EXIF**:
   `ImageUniqueID=VK-ODI50-183-2011` — not the flag, used as a salt candidate without
   success.

## Summary

The challenge's structural design was successfully reverse-engineered: native lib,
protocol framing, data blob layout, and the `deriveVaultKey` algorithm are all
fully understood. The flag was not recovered because the intended decryption path
could not be determined from the delivered artifacts. Standard AEAD modes (GCM, CBC,
CTR, ECB), standard KDF chains (PBKDF2→HKDF), every salt source available, and the
KDF parameters explicitly documented in the database were all tried against both
candidate ciphertexts (`wrapped_identity` and the P4 payload) with the confirmed
vault key. The negative result is broad enough to suggest either (a) a non-standard
crypto scheme I didn't identify, (b) a key derivation step with parameters not
present in the delivered metadata, or (c) a structural assumption about which
artifact is the real ciphertext that I got wrong.

## Tools Used

- `jadx` 1.5.0 — APK decompilation
- `radare2` / `rizin` — native lib disassembly
- `tshark` — pcapng parsing
- `sqlite3` — database inspection
- `exiftool` 13.55 — JPEG EXIF
- `pycryptodome` — AES-GCM/CBC/CTR/ECB
- `Python 3` — scripting and Kasiski/IC analysis
- `unzip` / `xxd` / `strings` — file inspection
