+++
title = "BCACTF 2025 Write-Up"
date = "2025-06-24"
tags = ["CTF", "Web"]
description = "Solving 10 challenges across Misc, Binary Exploitation, Crypto, and Web at BCACTF 2025."
+++
## Misc Category

### expletive

oh no! It seems like only some of the characters on my keyboard are working…

`nc challs.bcactf.com 38421`

```python
blacklist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def security_check(s):
    return any(c in blacklist for c in s) or s.count('_') > 50

BUFFER_SIZE = 36

while True:
    cmds = input("> ")

    if security_check(cmds):
        print("invalid input")
    else:
        if len(cmds) > BUFFER_SIZE:
            print(open("flag.txt", "r").read())
            break
        else:
            print("nope")
```

I noticed in the given server code two important things, first, all capital and small characters, and the numbers from 0 to 9 are blocked. Second, the buffer size is 36, so to print the flag, I should write something that skips the condition, but all characters are blocked too.

So I tried to write a special character like a semicolon and more than 36 sooooo

Our approach is true and the flag is **bcactf{fudG3_5hOo7_d4rn100}**

### Molasses

This GIF shows the flag letter-by-letter, but it's really slow and I don't want to wait all day. Maybe there's a faster way to get the flag?

I tried to make some forensic techniques as I used commands like `strings` `binwalk` `exiftool`, but nothing was useful, so I tried to drag a photo into a [photopea](https://www.photopea.com/), a useful online tool that clarifies if the given photo contains hidden layers or such.

After collecting the flag parts, our flag is **bcactf{is_it_gif_or_gif_a51fd7ace416}**

### Annoying

Sometimes things are more annoying than they are difficult.

[DLXENH.zip](https://play.bcactf.com/files/97bf5ef2f616239dad944354696f10d2/DLXENH.zip)

Truly, the caption is very true because the given file contains multiple zips, Idk how much :), but I tried to extract them 4 or 5 times until I got bored.

I thought in a very dumb approach I wasn't imagining that It would be that easy. I just `strings` the file and `grep` the flag format. LOOK AT THIS….

OUR FLAG IS HERE **bcactf{w3ll_th4t_w4s_4nn0y1ng_fca743ef043c1d8}**

## Binary Exploitation

### ShallowSeek

Our brand new AI, ShallowSeek, is the latest and greatest LLM created to date. You can talk to it about anything! (Well, anything the government lets you)

`nc challs.bcactf.com 44123`

```c
#include <stdio.h>
#include <string.h>

char *welcome = "Welcome to ShallowSeek!\nShallowSeek is a new, hyperadvanced AI that can answer any of your questions (that comply with government rules)! Ask away!\n";
char *begin = "Sorry, but \"";
char *end = "\" is beyond my current scope. Let's talk about something else.\n";

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    char input[64];
    char flag[64];
    fgets(flag, 64, fopen("flag.txt", "r"));
    printf("%s", welcome);
    while (1) {
        int i = 0;
        char c;
        while ((c = getchar()) != '\n') {
            input[i++] = c;
        };

        if (strlen(input) == 64) {
            printf("%s", "Invalid input: use less than 64 characters");
            continue;
        }

        printf("%s", begin);
        printf("%s", input);
        printf("%s", end);

        for (int j = 0; j < 64; j++) {
            input[j] = 0;
        }
    }
    return 0;
}
```

The program reads user input into a 64-byte buffer (`input`) without proper bounds checking, allowing an attacker to overflow into the adjacent `flag` buffer. Although there is a `strlen()` check to prevent buffer overflows, it occurs after the input is read, making it ineffective.

- The loop `while ((c = getchar()) != '\n')` writes to `input[i++]` without checking if `i` exceeds the buffer size.
- If exactly 64 bytes are sent (without a newline), the buffer is filled, leaving no null terminator.
- Since `strlen()` searches for a null terminator, reading 64 non-null bytes causes it to read beyond `input` into `flag`.
- The check `if (strlen(input) == 64)` fails to prevent the overflow because it happens too late.
- `printf("%s", input)` prints until a null byte is found.
- Since `input` has no null terminator, it leaks adjacent memory (`flag`).

SO the strategy I followed, I send exactly 64 bytes to fill the input completely, then `strlen(input)` reads into `flag`, making the check pass, `printf("%s", input)` leaks the flag because it continues printing into adjacent memory.

AND THAT IT IS ALL

Our flag is **bcactf{s0rRy_1_cAn7_741K_4B0U7_7ha7_R16h7_N0w_GfhNkl0iP2BK}**

### Printed

lol i fixed my printer. it just prints stuff now, you can use it now i guess.

(even if the initial prompt does not show up, the challenge should function as expected)

`nc challs.bcactf.com 37643`

```c
#include <stdio.h>

char flag[128];

void show(char* name, char* flag) {
    char newflag[50];
    snprintf(newflag, sizeof(newflag), name);
    printf("%s", newflag);
}

int main() {
    char name[45];
    printf(" > What's your name?  ");
    fgets(name, 45, stdin);

    FILE *fp = fopen("flag.txt", "r");
    if (fp) {
        fgets(flag, sizeof(flag), fp);
        fclose(fp);
    } else {
        flag[0] = '\0';
    }

    show(name, flag);

    return 0;
}
```

The provided C program reads a user-supplied name and prints it back using `snprintf()`. However, it contains a **critical format string vulnerability** due to improper handling of user input.

The `name` buffer is passed directly to `snprintf()` as the format string instead of being treated as data (use `%s`) as it should be:

```c
snprintf(newflag, sizeof(newflag), "%s", name); // Correct: name is data, not format
```

If a user submits format specifiers like `%s`, `%p`, or `%x`, the program will interpret them as commands rather than plain text. This allows attackers to:

- **Leak memory** (ex, `%p` exposes stack/pointer values).
- **Steal the flag** (ex, `%s` reads from memory if the flag's address is on the stack).

So first to implement my approach, I tried to write `%p` and see the output. It outputs some addresses, and our flag could be one of them, so I tried to print the flag using the `%n$s` format, and to understand this format:

**n** = Stack position (e.g., `%4$s` reads the 4th argument on the stack).

**%s** = Treats that argument as a pointer to a string and prints it.

As the vulnerable `snprintf(name)` call treats name as a format string, not plain text, so it worked in this challenge. Let's tryyyyyyyy

**HERE WEEE GOOOOOO** Our flag is in the 4th argument on the stack

**bcactf{mY_pr!nt3r_d0esnt_do_th@7_vrfhu}**

## Crypto

### BMovie

I cannot possibly believe that you could break into my highly secured, bee-crypted vault

`nc challs.bcactf.com 21649`

```typescript
import { hash, verify } from "jsr:@blackberry/bcrypt@0.17.0";

const encoder = new TextEncoder();
let uname: string, pwd: string, adminHash: string;

async function readLine(promptText: string): Promise<string> {
    await Deno.stdout.write(new TextEncoder().encode(promptText));
    const buf = new Uint8Array(1024);
    const n = <number> await Deno.stdin.read(buf);
    if (n === null) return "";
    return new TextDecoder().decode(buf.subarray(0, n)).trim();
}

async function readConfirm(promptText: string): Promise<boolean> {
    const answer = (await readLine(promptText + " (y/n): ")).toLowerCase();
    return answer.startsWith("y");
}

async function menu() {
    console.log(
        `Welcome! To begin, please register an admin account to hold the flag.`,
    );
    await signUp();
}

async function signUp() {
    uname = await readLine("Enter a username for the administrator: ");
    pwd = await readLine(
        "Enter a secure password for the administrator account: ",
    );
    adminHash = hash(encoder.encode(uname + ";" + pwd));

    const next = await readConfirm("Would you like to view the flag now?");
    if (next) {
        await login();
    } else {
        console.log("exiting...");
        Deno.exit(0);
    }
}

async function login() {
    const flag = await Deno.readTextFile("flag.txt");
    console.log("Choose an account to log into: ");
    const user = await readLine("Enter username: ");
    const password = await readLine("Enter password: ");
    if (user === uname || password === pwd) {
        console.log(
            "HEY. I sure hope you're not trying to break into the admin account.",
        );
        Deno.exit(0);
    }

    if (!verify(encoder.encode(user + ";" + password), adminHash)) {
        console.log("nahh you're not authorized to view the flag.");
        Deno.exit(0);
    }

    console.log(flag);
}

await menu();
```

The challenge asks us to register an admin account and then log in to view the flag. But the code tries to block access if you log in using the same username or password as the admin.

```typescript
if (user === uname || password === pwd) {
    console.log("HEY. I sure hope you're not trying to break into the admin account.");
    Deno.exit(0);
}
```

However, this check only compares the exact username and password strings, not the combined hash that controls access.

Later in the same function, it verifies the login by checking:

```typescript
verify(encoder.encode(user + ";" + password), adminHash)
```

This means that as long as we input the correct combo (`user + ";" + password`) that matches the admin's credentials exactly, we can still log in — even though we aren't allowed to use the same username or the same password alone.

After several attempts and a lot of effort, I finally discovered the input values that bypassed both conditions. The admin credentials were:

- **Admin Username:** `admin;`
- **Admin Password:** `pass`

The credentials that successfully bypassed the conditions were:

- **Username:** `admin`
- **Password:** `;pass`

HERE IS THE FLAGGGG **bcactf{!_c@n7_BEE_L1ev3_!t_fwrhiu}**

## ez-xor

Please be very ORZ and do some XORing.

`ICEjITYkOREpKyArBisRNyQkHRArODguJxAvJx0RKyUvIx0OIywmch0DNzAjJS0sHQAjMC0sHRcyJTAjJicmPw==`

From the name of the challenge, I know that I will use an XOR technique.

I had a ready script that used XOR, so I just made the script XOR with the flag format `bcactf{`:

```python
import base64

def decode_flag(encoded_str):
    decoded_bytes = base64.b64decode(encoded_str)

    for key in range(256):
        xor_result = bytes([b ^ key for b in decoded_bytes])

        if b'bcactf{' in xor_result:
            return xor_result.decode('utf-8')

    flag_start = b'bcactf{'
    potential_key = bytes([decoded_bytes[i] ^ flag_start[i] for i in range(len(flag_start))])

    key_length = len(potential_key)
    xor_result = bytes([decoded_bytes[i] ^ potential_key[i % key_length] for i in range(len(decoded_bytes))])

    return xor_result.decode('utf-8')

encoded_str = "ICEjITYkOREpKyArBisRNyQkHRArODguJxAvJx0RKyUvIx0OIywmch0DNzAjJS0sHQAjMC0sHRcyJTAjJicmPw=="

flag = decode_flag(encoded_str)
print(f"Decoded flag: {flag}")
```

And DONE, the flag is **bcactf{SkibiDiSuff_RizzleRme_Sigma_Land0_Auragon_Baron_Upgraded}**

## Web

### What?

Surmount the insurmountable.

The web [LINK](http://challs.bcactf.com:47861/)

The provided PHP code for the web:

```php
<?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $str1 = $_POST['string1'] ?? '';
        $str2 = $_POST['string2'] ?? '';

        $hash1 = md5($str1);
        $hash2 = md5($str2);

        if ($str1 == $str2 || strlen($str1) > 100 || strlen($str2) > 100 ||
            strlen($str1) < 5 || strlen($str2) < 5) {
            echo "No\n";
            exit;
        } else if ($hash1 == $hash2) {
            echo file_get_contents("flag.txt");
            exit;
        }
    }
?>

<!DOCTYPE html>
<html>
    <head>
        <title>What?</title>
    </head>
    <body>
        <form method="POST">
            <label for="string1">String 1:</label>
            <input type="text" name="string1" id="string1" required><br />

            <label for="string2">String 2:</label>
            <input type="text" name="string2" id="string2" required><br />

            <input type="submit" value="Compare hashes" />
        </form>
    </body>
</html>
```

To bypass the conditions in the code, we need to find two different strings (so `str1 != str2`), each with a length between 5 and 100 characters, that produce the same MD5 hash. This is known as an **MD5 collision**. I asked ChatGPT to make two different strings and have the same MD5 hash:

```python
str1 = `aabg7XSs`
str2 = `aabC9RqS`
```

And Done!!!

Our flag is **bcactf{wh0_kn0ws_4nym0r3_11fab08d769a}**

I have solved a same idea challenge before, The first one in my write-up [IEEE RAMADAN CTF](/@0xDblM/ieee-ramadan-fawazzer-ctf-writeup-d57265ce8ce9). Check it 🙌

### Source Under Control

It's my first time using Git. Hopefully nothing went unseen.

The web [LINK](http://challs.bcactf.com:28973/)

I started visiting the webpage, but nothing was there, just Hello :( so I viewed the code source, but nothing was there either.

So I returned to the challenge again, looking for any hints, but there weren't any given hints, but if we look read the description again we will find he told us "It's my first time using **Git**", so I considered git as a hint and I tried to write `/.git/` in the code source URL =>

`view-source:http://challs.bcactf.com:28973/.git/`

Then I found it — the `.git` directory was exposed!

Then I downloaded the git repository on my local machine to make it easy to search for the flag or any hints, so I wrote

`wget -r --no-parent http://challs.bcactf.com:28973/.git/`

And in my first step in analyzing the repo I wanted to search for any hints or deleted commits or flags so I used `git log -p`.

For those who don't know `git log -p` command It shows:

**Commit Metadata like:** Author name/email - Commit date - Commit message (often contains hints in CTFs).

**-p flag:**

- Exact lines added/removed in each file changed by the commit.
- Shown in unified diff format (`+` for additions, `-` for deletions).

Here we are again, after writing the command, I captured the flag immediately.

The flag is **bcactf{oops_didnt_mean_to_serve_that_c06677d3437e}**
