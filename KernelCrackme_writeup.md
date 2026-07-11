# KernelCrackme — Writeup

**Challenge:** Reverse a Linux kernel module (`.ko`) that registers `/dev/crackme`, work out the SHA‑256‑based check, and recover the flag.
**File:** `crackme.ko` — ELF 64‑bit x86‑64 relocatable, *not stripped*, with debug info.

---

## 1. First look

```
$ file crackme.ko
ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV),
BuildID[sha1]=4b6a1e72ca7f9d7a005ad3fd476fe7e8b2d53db3,
with debug_info, not stripped
```

Not stripped — great. The symbol table already tells the whole story:

```
$ nm crackme.ko | grep -E 'T|t [a-z]'
0000000030 t check_input
...
0000000250 t dev_write
0000000370 t dev_read
0000000450 t dev_open
0000000043 r __UNIQUE_ID_author232        ; author=CyberStrike 2026
...
0000000140 r expected_hash
```

There are exactly the functions you'd expect for a `file_operations`‑backed char device, plus a `check_input` routine and a symbol literally named `expected_hash`.

Strings confirm the theme:

```
sha256
crackme: digest failed: %d
wrong
crackme: crypto_alloc_shash failed: %ld
crackme: register_chrdev failed: %d
crackme: loaded … /dev/crackme ready (major %d)
cyberstrike{deadbeef1337c0dec0ffee00deadbeef}
CYBERSTRIKE_SALT_2026     (built in‑code, see below)
```

A `cyberstrike{…}` string is sitting in `.rodata.str1.8`. The challenge is to determine whether it's a decoy or the real flag — by reading the verifier.

---

## 2. The device protocol

`init_module` calls `__register_chrdev` with `fops = crackme_fops` (`.rodata+0x20`), then `class_create` + `device_create` to expose `/dev/crackme`.

The fops table wires four handlers:

| op | handler | role |
|----|---------|------|
| `open` | `dev_open` | allocate per‑fd state |
| `release` | `dev_release` | free it |
| `read` | `dev_read` | return result string |
| `write` | `dev_write` | ingest user input, run check |

### `dev_open` (`crackme.ko:0x450`)

```c
state = kmalloc(0x48, GFP_KERNEL);   // 72 bytes
filp->private_data = state;          // stored at +0xc8
```

The per‑fd state is a small struct:

```c
struct crackme_state {
    char  buf[64];   // +0x00  user input
    u64   len;       // +0x40  input length (after \n strip)
    u32   ok;        // +0x44  check_input result
    ...
};
```

### `dev_write` (`crackme.ko:0x250`)

1. `copy_from_user(state->buf, user_buf, min(count, 63))`
2. If the last byte is `\n`, drop it: `state->len = n - 1`.
3. NUL‑terminate: `state->buf[len] = 0`.
4. `state->ok = check_input(state)`.
5. Return bytes consumed.

So one `write(fd, "guess\n", 6)` triggers the whole verification.

### `dev_read` (`crackme.ko:0x370`)

Two interesting relocations:

```
0x393  R_X86_64_32S  .rodata.str1.8 + 0x30   ; "cyberstrike{…}\n"
0x3ad  R_X86_64_32S  .rodata.str1.1 + 0x25   ; "wrong\n"
```

The code:

```c
const char *msg = state->ok ? FLAG_STRING : "wrong\n";
size_t n = strnlen(msg, 0x2f);
copy_to_user(ubuf, msg + *off, min(count, n - *off));
```

So **the kernel itself hands back the flag when `check_input` returns nonzero.** The flag is the literal string sitting at `.rodata.str1.8 + 0x30`:

```
cyberstrike{deadbeef1337c0dec0ffee00deadbeef}
```

`check_input` is just the gatekeeper; the prize is already embedded in the module. We still need to prove the string is the *real* flag (not a decoy) by confirming the verifier's logic and expected hash are consistent with the salty "SHA256 challenge" described in `__UNIQUE_ID_description233`.

---

## 3. `check_input` (`crackme.ko:0x30`)

The heart of the module. Key disassembly, annotated:

```asm
check_input:
    ; take a stack copy of state->buf[0..len]
    mov  0x40(%rdi),%edx          ; edx = state->len
    lea  -1(%rdx),%ecx
    cmp  $0x3f,%ecx
    ja   .Ltoo_long               ; len-1 > 63  => reject
    ; ... memcpy(state->buf -> local[0x80]) ...

    ; append the 21‑byte literal salt after the user's input
    movabs $0x5254535245425943,%rsi   ; "CYBERSTR"  (little‑endian)
    mov   %rsi,(%rax)
    movabs $0x544c41535f454b49,%rsi   ; "IKE_SALT"
    mov   %rsi,0x8(%rax)
    movl  $0x3230325f,0x10(%rax)      ; "_202"
    movb  $0x36,0x14(%rax)            ; "6"
    ;   => appended salt = "CYBERSTRIKE_SALT_2026"   (len = 0x15)

    ; crypto_alloc_shash("sha256", 0, 0)
    mov  $0x0,%edi
    mov  $0xcc0,%esi                 ; CRYPTO_ALG_TYPE_SHASH
    call crypto_alloc_shash
    ; ... kmalloc a shash_desc ...

    ; crypto_shash_digest(desc, buf, len + 0x15, out)
    mov  0x40(%rbx),%edx            ; edx = state->len
    lea  -0xa5(%rbp),%rcx           ; rcx = &out (32 bytes)
    add  $0x15,%edx                  ; total = input_len + |salt|
    call crypto_shash_digest

    ; compare the 32‑byte digest against 4 embedded qwords
    movabs $0x9547a7037607b842,%rax  ; qword[0]
    cmp   %rax,-0xa5(%rbp)
    je    .Lq1
    ; fail
.Lq1:
    movabs $0x4b74b6ef7ddbdd80,%rax  ; qword[1]
    cmp   %rax,-0x9d(%rbp)
    jne   .Lfail
    movabs $0x4fefd7ae2f31ebac,%rax  ; qword[2]
    cmp   %rax,-0x95(%rbp)
    jne   .Lfail
    movabs $0xc1dbbb387da90879,%rax  ; qword[3]
    cmp   %rax,-0x8d(%rbp)
    jne   .Lfail
    xor   %eax,%eax                  ; pass (in this branch: ok=1)
.Lfail:
    mov   $0x1,%eax
    xor   $0x1,%eax                  ; ok = 0
```

The four comparison immediates, bytes little‑endian, are exactly the bytes laid out in `.rodata` at symbol `expected_hash`:

```
$ objdump -s -j .rodata crackme.ko
0140 42b80776 03a74795 80dddb7d efb6744b
0150 aceb312f aed7ef4f 7908a97d 38bbdbc1
```

So the target digest is

```
42b8077603a7479580dddb7defb6744baceb312faed7ef4f7908a97d38bbdbc1
```

### The verifier in C

```c
static int check_input(struct crackme_state *st)
{
    u8 out[32];

    if (st->len == 0 || st->len > 64) return 0;

    char buf[80];
    memcpy(buf, st->buf, st->len);
    memcpy(buf + st->len, "CYBERSTRIKE_SALT_2026", 21);  // 21 = 0x15

    struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) { pr_err(...); return 0; }

    int err = crypto_shash_digest(desc, buf, st->len + 21, out);
    crypto_destroy_tfm(tfm);
    if (err) { pr_err("crackme: digest failed: %d\n", err); return 0; }

    return memcmp(out, expected_hash, 32) == 0;
}
```

i.e.

```
SHA256( <input> || "CYBERSTRIKE_SALT_2026" )
    == 42b8077603a7479580dddb7defb6744baceb312faed7ef4f7908a97d38bbdbc1
```

Input length is capped at 63 bytes (one `char[64]`), which matches the hint "a SHA‑256‑based check" and our `char [64]` UBSan string in `.data`.

---

## 4. Recovering the flag

The flag is *not* the SHA‑256 preimage. The kernel returns it directly on success, and the success string is embedded in the module. Two roads converge on the same answer:

### Road A — static (what we did)

`dev_read`'s relocation to `.rodata.str1.8 + 0x30` resolves to the C string stored in‑binary:

```
$ objdump -s -j .rodata.str1.8 crackme.ko
0030 63796265 72737472 696b657b 64656164   cyberstrike{dead
0040 62656566 31333337 63306465 63306666   beef1337c0dec0ff
0050 65653030 64656164 62656566 7d0a0000   ee00deadbeef}...
```

Reading the bytes as ASCII:

```
cyberstrike{deadbeef1337c0dec0ffee00deadbeef}
```

That is the string the kernel copies to userspace when `state->ok` is nonzero, i.e. the flag. There is no decoy — the other `cyberstrike{…}` you might see while grepping `strings` *is* this same buffer.

### Road B — dynamic (would also work, on a box where you can insmod)

```bash
sudo insmod ./crackme.ko
sudo chmod 666 /dev/crackme
printf 'GUESS\n' > /dev/crackme
head -c 64 /dev/crackme
```

`GUESS` only needs to be any input whose SHA‑256‑with‑salt equals the embedded digest. Brute‑forcing a 32‑byte SHA‑256 preimage is infeasible, so static recovery (Road A) is the intended solution — the flag is shipped inside the module; the check is merely the *gate* the author put around returning it. The "Hard" difficulty comes from realizing that, in kernel‑land, a failed check just hands back `"wrong\n"` while a successful check hands back the embedded secret — so the workflow is "reverse the dispatcher, read the success pointer, follow the relocation".

### Sanity check

The expected digest is **not** `SHA256("cyberstrike{deadbeef1337c0dec0ffee00deadbeef}" || "CYBERSTRIKE_SALT_2026")`:

```python
>>> import hashlib
>>> hashlib.sha256(b"cyberstrike{deadbeef1337c0dec0ffee00deadbeef}"
...                 b"CYBERSTRIKE_SALT_2026").hexdigest()
'3918c8831a1926efb88e49eed169e17a7d1af2182a74eb6a5dc89d04cb55eb66'
```

That's expected — the *flag* is what the kernel hands back on success; it is *not* the password that satisfies the check. The check preimage (the admin password to trigger the success branch) is irrelevant to recovering the flag; what matters is what the success branch returns, and that string is `cyberstrike{deadbeef1337c0dec0ffee00deadbeef}`.

---

## 5. Flag

```
cyberstrike{deadbeef1337c0dec0ffee00deadbeef}
```

---

## Takeaways

- A `.ko` is just an ELF; the same tools (`nm`, `objdump -d/-s/-r`, `readelf`, `strings`) work. The relocations matter: kernel symbols are resolved at `insmod`, so the interesting references live in relocation entries like `R_X86_64_32S .rodata.str1.8 + 0x30`.
- For "verifier returns a string" challenges, always look at *both* branches — the failure branch and the success branch. The flag is often literally the success‑branch string embedded in the binary; you don't actually need to defeat the hash.
- SHA‑256‑based checks that *return a secret on success* can be defeated by static recovery of the secret even when the hash itself is unbreakable.
- Salt = `"CYBERSTRIKE_SALT_2026"` (author = `CyberStrike 2026`). Expected digest = `42b8077603a7479580dddb7defb6744baceb312faed7ef4f7908a97d38bbdbc1`.