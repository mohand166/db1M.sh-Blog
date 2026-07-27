+++
title = "No Notes CRLF Challenge | Hackena Ramadan CTF"
date = "2026-03-14"
tags = ["CTF", "Web"]
description = "Exploiting HTTP response splitting to steal cookies from an isolated bot using timing side-channel attacks."
difficulty = 'hard'
+++

> How I exploited HTTP response splitting to steal cookies from an isolated bot using only time measurements.

## The Challenge That Said "No"

When I first landed on the **No Notes hehe** challenge, I was greeted with a peculiar message:

> "Welcome to the secure notes application. We take security very seriously. After discovering XSS vulnerabilities, we have disabled the dynamic notes feature."

The landing page linked to a single static file: `/view/note.txt?name=note.txt`. That was it. No forms, no inputs, no obvious attack surface. Just a long-winded text file explaining why the developers decided to remove all features to achieve "perfect security."

I started by reading the bot code provided to understand what is going on:

```javascript
const playwright = require('playwright');
const express = require('express');

const app = express();
app.use(express.json());

const PORT = 3000;
const FLAG = process.env.FLAG || "Hackena{test_flag_123}";
const TARGET_DOMAIN = process.env.TARGET_DOMAIN || "localhost"; // web-nonotes:5001

async function visit(url) {
    let browser = null;
    try {
        console.log(`Visiting ${url}`);
        browser = await playwright.chromium.launch({
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });
        const context = await browser.newContext();

        const cookie = {
            name: 'flag',
            value: FLAG,
            domain: TARGET_DOMAIN,
            path: '/',
            httpOnly: false,
            secure: false,
            sameSite: 'Lax'
        };

        await context.addCookies([cookie]);

        const page = await context.newPage();
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 7000 });
        await page.waitForLoadState('networkidle', { timeout: 7000 }).catch(() => {});
        await page.waitForTimeout(1000);
        await browser.close();
        console.log(`Visited ${url}`);
    } catch (e) {
        console.log(`Error visiting ${url}: ${e.message}`);
        if (browser) await browser.close();
    }
}

app.post('/visit', async (req, res) => {
    const url = req.body.url;
    if (!url) {
        return res.status(400).send('Missing url');
    }

    if (!url.startsWith('http')) {
        return res.status(400).send('Invalid URL protocol');
    }

    await visit(url);
    res.send('done');
});

app.listen(PORT, () => {
    console.log(`Bot listening on port ${PORT}`);
});
```

**Key Findings:**

- Cookie name is `flag` containing the actual flag value.
- `httpOnly: false` means JavaScript can access it via `document.cookie`
- `TARGET_DOMAIN` is environment-controlled (affects which origin sees the cookie)
- `sameSite: 'Lax'` prevents the cookie from being sent on cross-site subrequests (like images or frames), but it is sent when the user navigates to the target site.

**Bot Timing Behavior**

- The bot navigates to your provided URL and waits until the basic HTML is parsed (`domcontentloaded`). It has a **7-second** hard limit.
- The bot waits until there are no more active network requests (images, scripts, API calls) for at least 500ms. Again, it has a **7-second** timeout. The `.catch(() => {})` ensures that even if the network never goes quiet, the script doesn't crash; it just moves on.
- This is a goldmine for **Side-Channel Timing Attacks**. By forcing the bot to make many slow network requests (e.g., requesting a non-existent image 1,000 times), an attacker can reliably keep the bot "busy" for the full 7 seconds.

After understanding the bot code clearly I decided to observe the request and the response for the `/view/note.txt?name=note.txt` endpoint on the burp.

I noticed some important headers:

- `Content-Disposition: inline; filename="note.txt"`
- `Content-Type: text/plain; charset=utf-8`
- `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';`

There is an important thing I noticed the filename parameter comes from the name parameter and no sanitization visible. Hmm **User input in a response header?** this is a huge proof about **CRLF Injection** existence.

## What's CRLF Injection?

CRLF stands for Carriage Return (`\r`, `%0D`) and Line Feed (`\n`,`%0A`) — the special characters that separate HTTP headers. If an application puts untrusted input into a header without sanitization, an attacker can inject new headers or even control the response body entirely.

Come back here! let's ensure we are right, let me inject this `?name=%22%0D%0AX-Pwned:%20true%0D%0A` :

PWNED. The server was blindly placing my input into the header. Now the question became: ***How far can I push this?***

## Response Splitting: Taking Full Control

A **CRLF injection** becomes truly dangerous when you can inject not just headers, but an entirely new response body. The trick is using **Transfer-Encoding: chunked**.

HTTP chunked encoding lets you specify the exact size of your content, then terminate the response. Anything after your chunk — like the original **note.txt** file — gets ignored by the browser.

We want to take full control of the browser to execute malicious code like steal a cookie, because XSS payloads are filtered, we use the response splitting technique.

Let's build a test payload:

```
name="%0D%0ATransfer-Encoding: chunked%0D%0AContent-Type: text/html%0D%0A%0D%0A3%0D%0Aabc%0D%0A0%0D%0A%0D%0A
```

Payload Structure:

- `%0D%0A` —> `\r\n` → Close the `Content-Disposition` header.
- Inject `Transfer-Encoding: chunked`
- Change `Content-Type` to `text/html`
- `%0D%0A` — Empty line (end of headers)
- `3` — Chunk size: 3 bytes
- `abc` — The actual HTML/JS content
- `0` — Terminating chunk (signals end of response)

Think of the browser like a person reading a script.

- **The Hijack:** Normally, the browser waits for the server to finish sending the whole file. But because you injected `Transfer-Encoding: chunked`, the browser stops looking at the total size and starts reading **chunks**.
- **The Execution:** Since you changed the `Content-Type` to `text/html`, the browser doesn't download a file — it opens a page. It reads your `3` bytes of `abc` (or your JS payload) and executes it immediately.
- **The Clean Exit (The 0):** This is the best part. The browser sees that `0` and thinks, ***the server is finished! I'll stop reading now.*** It completely ignores the rest of the real file that the server tries to send.

Now let's try making an alert using → `http://target.com/view/note.txt?name=%0D%0AContent-Type:text/html%0D%0A%0D%0A<script>alert(document.cookie)</script>`

Wait what?! why this not working. I will take a look again in the response. I remember there was a CSP header in the response: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';`

That means:

- Can't load external resources.
- Can't use inline JavaScript.
- **Can** load scripts from same origin (`self`).

So I'm injecting the response from the same domain, doesn't that count as `'self'`?

## The Two-Stage Attack

This is where it got creative. I needed to chain two CRLF injections:

**Stage 1:** Inject an HTML page

```html
<html><body>
<script src="/view/note.txt?name=[CRLF-PAYLOAD-2]"></script>
</body></html>
```

**Stage 2:** Make that script `src` URL return JavaScript instead of text

```javascript
// My malicious JavaScript here
document.cookie // Flag is here!
```

Because both responses come from the same origin, CSP's `script-src 'self'` allows the execution. Now we know how will be our attack chain look like.

## Character Extraction

I would extract the characters by the same way (binary search) but it took too much time and hanged the server so I asked Claude to optimize the code.

```python
# Stage 1: Binary search (3-4 queries)
while hi - lo > 23:
    mid = (lo + hi) // 2
    ok = oracle(f'document.cookie.charCodeAt({pos})>{mid}', base)
    if ok: lo = mid + 1
    else: hi = mid

# Stage 2: Parallel equality (5 workers, ~5s per char)
candidates = [c for c in "abcdefg...xyz0123..." if lo <= ord(c) <= hi]
results = oracle_parallel_batch([
    f'document.cookie.charCodeAt({pos})=={ord(c)}' 
    for c in candidates
], base)
```

Standard binary search was too slow and put too much stress on the server, so I switched to a **hybrid approach** to speed up the flag extraction:

- **The Bracket (Binary Search):** First, I used binary search to "zoom in" on the character. Instead of checking every possibility, I asked the bot a few "Higher or Lower?" questions. This quickly narrowed each character down from 128 possibilities to a tiny "bracket" of about 20 candidates.
- **The Blast (Parallel Testing):** Once the range was small enough, I stopped the binary search and tested all remaining candidates at once. By sending these requests in parallel, I didn't have to wait for them one by one.
- **The Result:** I simply looked for the **"Slowest Response."** The one request that triggered the 7-second delay told me exactly which character was correct, while the wrong guesses finished almost instantly.

## The Final Attack Chain

1. **Verify** server accepts CRLF injection (no bot needed).
2. **Test** JavaScript execution with making an alert.
3. **Find** which domain/origin has the cookie
4. **Extract** cookie length using binary search (~8 queries)
5. **Extract** each character using hybrid method (~50 seconds per char)

## The Solver Build

Run it using `python3 solver.py` and wait about 30 min for full flag.

**Final Notes**

The challenge is a strong example that removing a feature does not remove all attack surface if response construction still trusts user input. The critical sink here is header generation, not HTML template rendering.

Happy Hacking :)
