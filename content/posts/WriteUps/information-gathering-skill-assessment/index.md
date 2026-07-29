+++
title = 'Information Gathering Skill Assessment | CWES Path on HTB'
date = '2026-01-05T08:36:42-04:00'
draft = false
slug = 'information-gathering-skill-assessment'
description = 'Reconnaissance methodology covering DNS enumeration, WHOIS lookups, subdomain discovery, and web footprinting to map an attack surface.'
tags = ["Web", "HTB"]
difficulty = 'hard'
+++

![](https://miro.medium.com/v2/resize:fit:792/1*x9V5H3RDvJxIkp1AnOEy3w.jpeg)

Hello everyone

In this article, I’ll share my approach to solving the **Information Gathering skill assessment** on Hack The Box, sharing the methodology and tools I used along the way.

### What is Web Reconnaissance and why It Matters ?

Web Reconnaissance is the **Information Gathering**
 phase of a penetration test. It aims to map the target’s digital 
footprint and identify entry points before an actual attack begins.

### Core Objectives

**Asset Identification:** Mapping subdomains, IPs, and tech stacks.

**Data Discovery:** Finding leaked backups, config files, or internal docs.

**Attack Surface Analysis:** Pinpointing misconfiguration and vulnerabilities.

**Intelligence Gathering:** Collecting emails and employee data for Social Engineering.

With a quick overview of information gathering out of the way, you can explore **all my notes for this module → Check this**.

Now, let’s jump straight into the assessment.

### **Q1: What is the IANA ID of the registrar of the inlanefreight.com domain?**

> **IANA** stands for **Internet Assigned Numbers Authority**.
> 
> 
> It’s the organization that:
> 
> - Manages **IP address allocations**.
> - Manages **Domain Name System (DNS) root zones**.
> - Assigns **protocol numbers**, port numbers, and other internet identifiers.

We can obtain the **IANA ID** using the `whois` command, which is commonly used to query information such as the **registrar**, **registrant (administrative contact)**, **name servers**, and related details.

Before running any commands, we first need to add the **target IP address and domain** to the `/etc/hosts` file.

To do this, open the `/etc/hosts` file using:

```
sudo nano /etc/hosts
```

Then add the **target IP and domain** as shown below:

![](https://miro.medium.com/v2/resize:fit:463/1*q_4H9Duy29Dw0yoANuBR5w.png)

This step should be repeated for **each domain or subdomain** you plan to use.

### What is the `/etc/hosts` file?

The `/etc/hosts` file is a **local mapping of IP addresses to hostnames**
 on your system. When you try to access a domain, your computer first 
checks this file to see if there’s a specific IP associated with that 
domain **before querying DNS servers**.

By adding the **target IP and domain/subdomain** to `/etc/hosts` ,it **forces your system to resolve the domain to the IP you specify**, which is crucial for controlled testing in penetration testing.

Turning back to our question, I used `whois` and done:

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*CWLVUJNseV4JJWjJYpBqIw.png)

### Q2: What http server software is powering the inlanefreight.htb site on the target system?

To know what is the web server is running we can use whatweb command, which is useful to **identify technologies, frameworks, CMSs, and server details** used by a website:

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*UaWbU5aA63ijBwA6QiRVcw.png)

**Small Note:** I put the port (49249) in the URL because the challenge doesn’t use the default port (80) for the HTTP requests

### Q3: What is the API key in the hidden admin directory that you have discovered on the target system?

Hmmm Q3 which takes a bit little more time from me :(

The hidden directory clue suggested a **hidden subdomain or directory**, so I used `curl` to inspect the **HTTP request and response**. Unfortunately, it didn’t reveal anything useful, aside from a simple HTML header.

I realize an important thing that the IP and the domain we put in the `/etc/hosts` can be treated as vhost.

**What is Virtual Host (VHOST) ?**

A **virtual host (VHOST)** allows a single **IP address** to host **multiple websites**, where each site is identified by a different **`Host` header** in the HTTP request.

For example, `example.com`, `admin.example.com`, and `api.example.com` can all resolve to the same IP address, yet serve completely different content based on the requested `hostname`.

After identifying the need to search for hidden virtual hosts, I used **Gobuster** in **VHOST enumeration mode**. Instead of fuzzing URL paths, this technique fuzzes the **`Host` header**, allowing us to discover subdomains configured on the web server but not publicly accessible.

```
gobuster vhost \
-u http://inlanefreight.htb:39225 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
--append-domain
```

It takes more time, but it is totally worth it:

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*NrmRb8fWEV39GBw4IETNwA.png)

We found a subdomain for our target, let’s explore it using our browser.

As expected nothing literally

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*ZReA6cjVdAgHznOblJ5Cyg.png)

So it’s time to fuzzzzzzzz

Before fuzzing I added the subdomain in the `hosts` file

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*YJOJNZvP_AjwaKtBI-wGuw.png)

I used `ffuf` to discover any directories in this domain, **the command used:**

```
ffuf -u http://[subdomain].inlanefreight.htb:39225/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-e .html \
-fs 120
```

`FUZZ` is a placeholder that FFUF replaces with each word from the wordlist.

- `w /usr/share/seclists/Discovery/Web-Content/common.txt` the wordlist I used, you can get it from this **repo**
- `fs 120` (filter size): remove the responses with the size of 120 byte helping us ignore the false responses.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*XR-8sKYKH36NdI-6Ikmkyw.png)

After browsing `robots.txt`

![](https://miro.medium.com/v2/resize:fit:511/1*T3A0300YafCybnQdttIPRg.png)

Finally, we discovered the hidden path. To inspect the API, we simply made a request using `curl`.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*qBTKVSekGKKjcyYRZ-g9OA.png)

**Q4: After crawling the inlanefreight.htb domain on the target system, what is the email address you have found?**

The question push us to use crawler so I used **ReconSpider,** so let’s install it together:

```
pip3 install scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
```

You
 can use it in your own machine but it requires using environment 
(search how to setup it ✋), I used pwnbox in HTB because there was a 
trouble in my kali lol

whatever, after installing it using

```
python3 ReconSpider.py http://[subdomain].inlanefreight.htb:39225
```

I didn’t get anything what’s wronggg??

After trying all possibilities, I decide to fuzz again to any subdomains using `Gobuster` again with the same wordlist (this decision is a hint to be honst :)

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*TzATJw4X7fgyh-aPleWlfw.png)

We found another subdomain, after adding it to `hosts` file and trying `ReconSpider` again we have got something (ReconSpider saves the results in JSON format)

So let’s cat it

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*1YRWgdKDlP3rZSaYS9ckrQ.png)

We got the email 👌

**Q4: What is the API key the inlanefreight.htb developers will be changing too?**

This requires us to observe the JSON again carefully so I used my character haha

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*X_8MnycbIiRN5lQdYkkvnw.jpeg)

I found a comment mentioning that the API will be changing to

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:792/1*I-848fXucxxQvt43QeqdWQ.png)

***That’s it for this challenge. See you in the next one!***