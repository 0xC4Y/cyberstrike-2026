---
title: "HeavyMeta"
ctf: "CyberStrike"
date: 2026-07-11
category: web
difficulty: very-hard
points: 475
flag_format: "cyberstrike{...}"
author: "retr0"
---

# HeavyMeta

## Summary

A "metadata processing API" fronted by Nginx and backed by Gunicorn exposes an admin panel restricted to localhost. The backend trusts the `X-Forwarded-For` header to identify the originating client, and Nginx is not overwriting the client-supplied value, so a direct header injection makes the backend treat the request as local — no real HTTP request smuggling required.

## Solution

### Step 1: Recon the trust boundary

The landing page advertises three routes:

- `POST /submit` — submit metadata
- `GET /health` — health check
- `GET /admin` — "Admin panel (localhost only)"

A direct `GET /admin` returns `403 Forbidden: admin panel is localhost-only`. The `Server: gunicorn` header confirms Nginx is proxying to Gunicorn, which is the classic setup where the backend decides "is this local?" from a forwarded IP header rather than the actual socket peer.

### Step 2: Spoof the forwarded IP header

Gunicorn/Flask-style backends commonly read `X-Forwarded-For` (set by the edge proxy) to reconstruct the client IP. If Nginx is configured to *append* rather than *set* that header (or not to touch it at all), an attacker-supplied value reaches the backend unchanged. Send the admin request with a forged localhost origin:

```bash
curl -s http://chal.csc-snist.live:49881/admin \
     -H "X-Forwarded-For: 127.0.0.1"
```

Output:

```
Admin panel. FLAG=cyberstrike{5b5306d9da914b86ddb5222eba46f984}
```

A quick control test confirms the bypass is header-specific: the same request with `X-Real-IP: 127.0.0.1` instead still returns `403`, so the backend keys exclusively on `X-Forwarded-For`.

## Flag

```
cyberstrike{5b5306d9da914b86ddb5222eba46f984}
```
