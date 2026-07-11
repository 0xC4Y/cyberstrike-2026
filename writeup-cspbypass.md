---
title: "CSPBypass"
ctf: "CSC-SNIST"
date: 2026-07-10
category: web
difficulty: insane
points: 500
flag_format: "cyberstrike{...}"
author: "retr0"
---

# CSPBypass

## Summary

DataBoard is an analytics-powered dashboard behind a strict CSP (`nonce` + `strict-dynamic` + a whitelisted analytics origin). The flag is stored in a cookie on the DataBoard app. Despite the elaborate CSP + JSONP bypass chain available via the whitelisted analytics provider's `/track` endpoint (which reflects an unsanitized `callback` parameter), the flag cookie was set directly on every response to the main page — no admin-bot interaction required.

## Solution

### Step 1: Inspect the main page and CSP

The DataBoard home page (`http://chal.csc-snist.live:46082/`) returns a strict CSP and, notably, a `Set-Cookie` header carrying the flag:

```http
Content-Security-Policy: script-src 'nonce-...' 'strict-dynamic' https://analytics.challenge.local:1338; object-src 'none'; base-uri 'none';
Set-Cookie: flag=cyberstrike{...}; HttpOnly=false; SameSite=None; Secure=false
```

The cookie is `HttpOnly=false`, `SameSite=None`, and `Secure=false` — accessible to client-side JavaScript and sent cross-site. The page also loads `https://analytics.challenge.local:1338/analytics.js` with a nonce.

### Step 2: Retrieve the flag

```bash
curl -s -i http://chal.csc-snist.live:46082/ | grep -i set-cookie
```

Actual output:

```
Set-Cookie: flag=cyberstrike{1e9bfe5094e756f91cc9a1a504b74bed}; HttpOnly=false; SameSite=None; Secure=false
```

## Intended chain (for reference)

The challenge was designed for a JSONP-under-`strict-dynamic` CSP bypass:

1. The whitelisted analytics provider (`https://analytics.challenge.local:1338`) exposes `/track?event=...&callback=CALLBACK`, reflecting the `callback` value into the JS response with **no sanitization**:
   ```
   alert(document.cookie)//({"event":"pageview","ts":...,"ok":true});
   ```
2. `analytics.js` itself calls `document.createElement('script')` and appends it to `<head>`, so any script loaded from the whitelisted origin propagates trust under `strict-dynamic`.
3. Injecting `<script src="https://analytics.challenge.local:1338/track?event=x&callback=PAYLOAD">` (via the 404 page or `/report`-driven admin visit) executes `PAYLOAD` under the CSP, exfiltrating `document.cookie`.

In this instance the flag was exposed directly in the response cookie, so the bypass chain was not needed to retrieve it.

## Flag

```
cyberstrike{1e9bfe5094e756f91cc9a1a504b74bed}
```
